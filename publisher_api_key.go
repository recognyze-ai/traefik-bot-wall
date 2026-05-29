package traefik_bot_wall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	publisherRotationLockDuration = 2 * time.Minute
	publisherMinRotationSleep     = time.Minute
)

type publisherKeyState struct {
	Secret       string
	KeyID        string
	Name         string
	Status       string
	CreationDate string
	Expiration   string
	RevokedKeyID string
	RotatedAt    string
	LastMetaSync string
	NextRotation string
	LastRotError string
}

// PublisherKeyManager maintains the live publisher API key (state file + proactive rotation).
type PublisherKeyManager struct {
	bootstrapSecret   string
	stateFile         string
	apiBase           string
	rotationEnabled   bool
	bufferDays        int
	metadataInterval  time.Duration
	encryptAtRest     bool
	encKey            []byte
	allowInsecureHTTP bool
	httpClient        *http.Client

	mu          sync.RWMutex
	state       publisherKeyState
	rotateUntil time.Time

	loopOnce sync.Once
	stopCh   chan struct{}
}

// NewPublisherKeyManager loads state and prepares the manager. Call StartRotationLoop when rotation is enabled.
func NewPublisherKeyManager(cfg *parsedConfig) (*PublisherKeyManager, error) {
	if cfg == nil || strings.TrimSpace(cfg.PublisherLogsURL) == "" {
		return nil, nil
	}

	apiBase, err := resolvePublisherAPIBaseURL(cfg.PublisherLogsURL, cfg.PublisherAPIBaseURL)
	if err != nil {
		return nil, err
	}

	m := &PublisherKeyManager{
		bootstrapSecret:   strings.TrimSpace(cfg.PublisherAPIKey),
		stateFile:         strings.TrimSpace(cfg.PublisherAPIKeyStateFile),
		apiBase:           apiBase,
		rotationEnabled:   cfg.publisherAPIKeyRotationEnabled,
		bufferDays:        cfg.publisherAPIKeyRotationBufferDays,
		metadataInterval:  cfg.publisherAPIKeyMetadataSyncInterval,
		encryptAtRest:     cfg.publisherAPIKeyEncryptAtRest,
		allowInsecureHTTP: cfg.AllowInsecureBotRulesURL,
		httpClient:        &http.Client{Timeout: 15 * time.Second},
		stopCh:            make(chan struct{}),
	}

	if m.stateFile == "" {
		m.stateFile = defaultPublisherAPIKeyStateFile
	}

	if m.encryptAtRest {
		key, err := loadPublisherEncryptionKey(cfg.PublisherAPIKeyEncryptionKeyFile)
		if err != nil {
			return nil, err
		}
		m.encKey = key
	}

	if err := m.loadStateFromDisk(); err != nil {
		return nil, err
	}

	if m.state.Secret == "" {
		m.state.Secret = m.bootstrapSecret
	} else if m.state.Secret != m.bootstrapSecret {
		log.Printf("[botwall] publisher API key loaded from state file (bootstrap YAML not used for shipping)")
	}

	if m.state.KeyID == "" {
		m.state.KeyID = keyIDFromSecret(m.state.Secret)
	}

	return m, nil
}

func resolvePublisherAPIBaseURL(publisherLogsURL, override string) (string, error) {
	if base := strings.TrimSpace(override); base != "" {
		return strings.TrimRight(base, "/"), nil
	}
	u, err := url.Parse(strings.TrimSpace(publisherLogsURL))
	if err != nil || !u.IsAbs() {
		return "", fmt.Errorf("invalid publisherLogsURL for API base derivation")
	}
	path := u.Path
	for _, suffix := range []string{"/publisher/logs/", "/publisher/logs"} {
		if strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	if path == "" || path == "/" {
		return "", fmt.Errorf("cannot derive publisher API base from publisherLogsURL path %q", u.Path)
	}
	u.Path = strings.TrimRight(path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func keyIDFromSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if i := strings.Index(secret, "_"); i > 0 {
		return secret[:i]
	}
	return secret
}

func maskAPISecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 8 {
		return "sk_***"
	}
	return secret[:min(7, len(secret))] + "…" + secret[len(secret)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *PublisherKeyManager) loadStateFromDisk() error {
	raw, err := os.ReadFile(m.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	st, err := decodePublisherKeyStateFile(raw, m.encryptAtRest, m.encKey)
	if err != nil {
		return err
	}
	m.state = st
	return nil
}

func (m *PublisherKeyManager) saveStateLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0o755); err != nil {
		return err
	}
	raw, err := encodePublisherKeyStateFile(m.state, m.encryptAtRest, m.encKey)
	if err != nil {
		return err
	}
	tmp := m.stateFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.stateFile)
}

// Secret returns the active API key for X-API-KEY headers.
func (m *PublisherKeyManager) Secret() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.Secret
}

// StartRotationLoop runs proactive metadata sync and rotation scheduling.
func (m *PublisherKeyManager) StartRotationLoop() {
	if m == nil || !m.rotationEnabled {
		return
	}
	m.loopOnce.Do(func() {
		log.Printf("[botwall] publisher API key rotation loop enabled stateFile=%s bufferDays=%d syncInterval=%s",
			m.stateFile, m.bufferDays, m.metadataInterval)
		go m.runRotationLoop()
	})
}

func (m *PublisherKeyManager) runRotationLoop() {
	if err := m.RefreshMetadata(); err != nil {
		log.Printf("[botwall] publisher API key initial metadata sync failed: %v", err)
	}
	m.scheduleDueRotation()

	ticker := time.NewTicker(m.metadataInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.RefreshMetadata(); err != nil {
				log.Printf("[botwall] publisher API key metadata sync failed: %v", err)
			}
			if err := m.MaybeRotateProactive(); err != nil {
				log.Printf("[botwall] publisher API key proactive rotation failed: %v", err)
			}
			m.scheduleDueRotation()
		}
	}
}

func (m *PublisherKeyManager) scheduleDueRotation() {
	m.mu.RLock()
	next := parseRFC3339Time(m.state.NextRotation)
	m.mu.RUnlock()
	if next.IsZero() {
		return
	}
	delay := time.Until(next)
	if delay < publisherMinRotationSleep {
		delay = publisherMinRotationSleep
	}
	go func(d time.Duration) {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-m.stopCh:
			return
		case <-timer.C:
			if err := m.MaybeRotateProactive(); err != nil {
				log.Printf("[botwall] publisher API key scheduled rotation failed: %v", err)
			}
			m.scheduleDueRotation()
		}
	}(delay)
}

// RefreshMetadata fetches GET current and updates state metadata.
func (m *PublisherKeyManager) RefreshMetadata() error {
	if m == nil {
		return nil
	}
	key, err := m.fetchCurrentKeyMetadata()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if key.KeyID != "" {
		m.state.KeyID = key.KeyID
	}
	m.state.Name = key.Name
	m.state.Status = key.Status
	m.state.CreationDate = key.CreationDate
	m.state.Expiration = key.ExpirationDate
	m.state.LastMetaSync = time.Now().UTC().Format(time.RFC3339)
	m.state.NextRotation = formatRotationDueTime(key.ExpirationDate, m.bufferDays)
	m.state.LastRotError = ""
	if err := m.saveStateLocked(); err != nil {
		return err
	}
	return nil
}

type apiKeyDetails struct {
	KeyID          string `json:"key_id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	CreationDate   string `json:"creation_date"`
	ExpirationDate string `json:"expiration_date"`
}

// MaybeRotateProactive rotates when within the buffer window before expiration.
func (m *PublisherKeyManager) MaybeRotateProactive() error {
	if m == nil || !m.rotationEnabled {
		return nil
	}
	m.mu.RLock()
	st := m.state
	m.mu.RUnlock()
	if !IsRotationDue(st.Expiration, m.bufferDays, time.Now().UTC()) {
		return nil
	}
	if status := strings.ToLower(strings.TrimSpace(st.Status)); status != "" && status != "active" {
		log.Printf("[botwall] proactive API key rotation skipped: status=%q", st.Status)
		return nil
	}
	return m.rotate()
}

// IsRotationDue reports whether now is at or past expiration minus bufferDays.
func IsRotationDue(expirationDate string, bufferDays int, now time.Time) bool {
	exp := parseRFC3339Time(expirationDate)
	if exp.IsZero() || bufferDays < 0 {
		return false
	}
	due := exp.AddDate(0, 0, -bufferDays)
	return !now.Before(due)
}

func formatRotationDueTime(expirationDate string, bufferDays int) string {
	exp := parseRFC3339Time(expirationDate)
	if exp.IsZero() {
		return ""
	}
	return exp.AddDate(0, 0, -bufferDays).UTC().Format(time.RFC3339)
}

func parseRFC3339Time(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	return time.Time{}
}

func (m *PublisherKeyManager) acquireRotateLock() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.rotateUntil.IsZero() && time.Now().Before(m.rotateUntil) {
		return false
	}
	m.rotateUntil = time.Now().Add(publisherRotationLockDuration)
	return true
}

func (m *PublisherKeyManager) releaseRotateLock() {
	m.mu.Lock()
	m.rotateUntil = time.Time{}
	m.mu.Unlock()
}

func (m *PublisherKeyManager) rotate() error {
	if !m.acquireRotateLock() {
		return errors.New("publisher API key rotation already in progress")
	}
	defer m.releaseRotateLock()

	candidates := m.rotateKeyIDCandidates()
	var lastErr error
	for _, keyID := range candidates {
		result, err := m.putRotate(keyID)
		if err != nil {
			lastErr = err
			continue
		}
		m.mu.Lock()
		m.state.Secret = result.Secret
		if result.KeyID != "" {
			m.state.KeyID = result.KeyID
		}
		if result.Name != "" {
			m.state.Name = result.Name
		}
		if result.RevokedKeyID != "" {
			m.state.RevokedKeyID = result.RevokedKeyID
		}
		m.state.Status = "active"
		m.state.RotatedAt = time.Now().UTC().Format(time.RFC3339)
		m.state.LastRotError = ""
		m.mu.Unlock()

		if err := m.RefreshMetadata(); err != nil {
			log.Printf("[botwall] metadata refresh after rotate failed: %v", err)
		}

		log.Printf("[botwall] publisher API key rotated key_id=%s revoked_key_id=%s secret=%s",
			result.KeyID, result.RevokedKeyID, maskAPISecret(result.Secret))
		return nil
	}
	if lastErr != nil {
		m.mu.Lock()
		m.state.LastRotError = lastErr.Error()
		_ = m.saveStateLocked()
		m.mu.Unlock()
	}
	return lastErr
}

func (m *PublisherKeyManager) rotateKeyIDCandidates() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	seen := map[string]struct{}{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	add(m.state.KeyID)
	add("current")
	return out
}

type rotateAPIResult struct {
	Secret       string
	KeyID        string
	Name         string
	RevokedKeyID string
}

func (m *PublisherKeyManager) apiKeyURL(keyID string, query url.Values) string {
	base := m.apiBase + "/account/publisher/api-keys/" + url.PathEscape(strings.TrimSpace(keyID)) + "/"
	if len(query) > 0 {
		return base + "?" + query.Encode()
	}
	return base
}

func (m *PublisherKeyManager) doAPIRequest(method, targetURL string, body []byte) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", m.Secret())
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp, respBody, err
}

func (m *PublisherKeyManager) fetchCurrentKeyMetadata() (apiKeyDetails, error) {
	target := m.apiKeyURL("current", nil)
	resp, body, err := m.doAPIRequest(http.MethodGet, target, nil)
	if err != nil {
		return apiKeyDetails{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiKeyDetails{}, fmt.Errorf("GET current returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Key apiKeyDetails `json:"key"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return apiKeyDetails{}, err
	}
	if strings.TrimSpace(envelope.Key.KeyID) == "" {
		return apiKeyDetails{}, errors.New("GET current response missing key")
	}
	return envelope.Key, nil
}

func (m *PublisherKeyManager) putRotate(keyID string) (rotateAPIResult, error) {
	q := url.Values{"op": []string{"rotate"}}
	target := m.apiKeyURL(keyID, q)
	resp, body, err := m.doAPIRequest(http.MethodPut, target, []byte("{}"))
	if err != nil {
		return rotateAPIResult{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return rotateAPIResult{}, fmt.Errorf("rotate %s: 404", keyID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return rotateAPIResult{}, fmt.Errorf("rotate %s returned %d: %s", keyID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Secret       string `json:"secret"`
		KeyID        string `json:"key_id"`
		Name         string `json:"name"`
		RevokedKeyID string `json:"revoked_key_id"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return rotateAPIResult{}, err
	}
	if strings.TrimSpace(envelope.Secret) == "" {
		return rotateAPIResult{}, errors.New("rotate response missing secret")
	}
	return rotateAPIResult{
		Secret:       strings.TrimSpace(envelope.Secret),
		KeyID:        strings.TrimSpace(envelope.KeyID),
		Name:         strings.TrimSpace(envelope.Name),
		RevokedKeyID: strings.TrimSpace(envelope.RevokedKeyID),
	}, nil
}

// publisherKeyStateHasSecret reports whether the state file contains a usable secret.
func publisherKeyStateHasSecret(stateFile string, encrypt bool, encKey []byte) bool {
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		return false
	}
	st, err := decodePublisherKeyStateFile(raw, encrypt, encKey)
	if err != nil {
		return false
	}
	return strings.TrimSpace(st.Secret) != ""
}
