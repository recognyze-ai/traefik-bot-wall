package botwall

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type resolverState struct {
	FetchedAt      time.Time `json:"fetched_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	NextRefreshAt  time.Time `json:"next_refresh_at"`
	ETag           string    `json:"etag"`
	LastModified   string    `json:"last_modified"`
	RecognyzeURL   string    `json:"recognyze_url"`
	ProtectedPaths []string  `json:"protected_paths"`
	Source         string    `json:"source"`
	LastError      string    `json:"last_error"`
}

// ProtectedResolver resolves and caches protected paths for request-time checks.
//
// Discovery precedence follows the architecture contract:
//  1. configured recognyzeURL
//  2. robots.txt Recognyze: directive fallback
//
// The resolver keeps an in-memory snapshot for hot-path checks and persists that
// snapshot to disk for restart continuity.
type ProtectedResolver struct {
	cfg        *parsedConfig
	http       *http.Client
	mu         sync.RWMutex
	state      resolverState
	refreshing bool
}

// NewProtectedResolver initializes the resolver and restores the last snapshot
// when available. If no schedule exists yet, refresh is eligible immediately.
func NewProtectedResolver(cfg *parsedConfig) *ProtectedResolver {
	r := &ProtectedResolver{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
		state: resolverState{
			Source: "empty",
		},
	}
	r.loadSnapshot()
	if r.state.NextRefreshAt.IsZero() {
		r.state.NextRefreshAt = time.Now()
	}
	return r
}

// IsProtected performs request-time path evaluation against the current in-memory
// protected-path index and reports source/cache metadata for observability.
//
// It may trigger a background refresh when the refresh window is due, while still
// serving with the last known snapshot.
func (r *ProtectedResolver) IsProtected(req *http.Request) (bool, string, string) {
	r.refreshIfDue(req)

	r.mu.RLock()
	state := r.state
	refreshing := r.refreshing
	r.mu.RUnlock()

	cacheStatus := "fresh"
	now := time.Now()
	switch {
	case len(state.ProtectedPaths) == 0:
		cacheStatus = "empty"
	case now.After(state.ExpiresAt):
		cacheStatus = "stale"
	}
	if refreshing {
		cacheStatus = "refreshing"
	}

	path := req.URL.Path
	protected := matchesProtectedPath(path, state.ProtectedPaths)
	return protected, state.Source, cacheStatus
}

// refreshIfDue starts at most one asynchronous refresh when nextRefreshAt is due.
// The refresh is intentionally non-blocking so request-time decisions stay fast.
func (r *ProtectedResolver) refreshIfDue(req *http.Request) {
	now := time.Now()
	r.mu.RLock()
	refreshing := r.refreshing
	nextRefreshAt := r.state.NextRefreshAt
	r.mu.RUnlock()
	if refreshing || now.Before(nextRefreshAt) {
		return
	}

	r.mu.Lock()
	// Re-check under write lock to preserve single in-flight refresh invariant.
	if r.refreshing || time.Now().Before(r.state.NextRefreshAt) {
		r.mu.Unlock()
		return
	}
	r.refreshing = true
	r.mu.Unlock()

	host := req.Host
	scheme := requestScheme(req)
	go func() {
		defer func() {
			r.mu.Lock()
			r.refreshing = false
			r.mu.Unlock()
		}()
		if err := r.refresh(host, scheme); err != nil {
			log.Printf("[botwall] recognyze refresh failed: %v", err)
		}
	}()
}

// refresh resolves the discovery URL, fetches/updates protected paths, and rotates
// cache lifecycle fields (fetchedAt, expiresAt, nextRefreshAt, etag, lastModified).
//
// On errors, it keeps serving the existing snapshot and schedules a retry window.
func (r *ProtectedResolver) refresh(host, scheme string) error {
	discoveryURL := strings.TrimSpace(r.cfg.RecognyzeURL)
	source := "config"
	if discoveryURL == "" {
		robotsURL := strings.TrimSpace(r.cfg.RobotsTxtURL)
		if robotsURL == "" {
			robotsURL = scheme + "://" + host + "/robots.txt"
		}
		robotsBody, _, _, err := r.fetchWithConditionals(robotsURL, "", "")
		if err != nil {
			return err
		}
		discoveryURL = extractRecognyzeURL(string(robotsBody), robotsURL)
		source = "robots"
		if discoveryURL == "" {
			r.mu.Lock()
			r.state.NextRefreshAt = time.Now().Add(30 * time.Minute)
			r.state.LastError = "recognyze directive not found"
			r.mu.Unlock()
			return nil
		}
	}

	r.mu.RLock()
	etag := r.state.ETag
	lastMod := r.state.LastModified
	r.mu.RUnlock()

	body, newEtag, newLastMod, err := r.fetchWithConditionals(discoveryURL, etag, lastMod)
	if err != nil {
		r.mu.Lock()
		r.state.NextRefreshAt = time.Now().Add(15 * time.Minute)
		r.state.LastError = err.Error()
		r.mu.Unlock()
		return err
	}

	paths := r.state.ProtectedPaths
	if len(body) > 0 {
		paths = parseRecognyzePaths(string(body))
	}

	now := time.Now()
	expiresAt := now.Add(r.cfg.cacheTTL)
	jitter := time.Duration(rand.Int63n(int64(r.cfg.refreshJitter)))
	nextRefresh := expiresAt.Add(-r.cfg.refreshBeforeExpiry).Add(jitter)

	r.mu.Lock()
	r.state = resolverState{
		FetchedAt:      now,
		ExpiresAt:      expiresAt,
		NextRefreshAt:  nextRefresh,
		ETag:           fallbackString(newEtag, etag),
		LastModified:   fallbackString(newLastMod, lastMod),
		RecognyzeURL:   discoveryURL,
		ProtectedPaths: paths,
		Source:         source,
		LastError:      "",
	}
	r.mu.Unlock()

	return r.saveSnapshot()
}

// loadSnapshot restores resolver state from cacheFile when present.
func (r *ProtectedResolver) loadSnapshot() {
	body, err := os.ReadFile(r.cfg.CacheFile)
	if err != nil {
		return
	}
	var snapshot resolverState
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return
	}
	r.state = snapshot
}

// saveSnapshot persists the current resolver state for restart continuity.
func (r *ProtectedResolver) saveSnapshot() error {
	r.mu.RLock()
	snapshot := r.state
	r.mu.RUnlock()
	return writeJSON(r.cfg.CacheFile, snapshot)
}

// extractRecognyzeURL parses a Recognyze: directive from robots.txt content and
// resolves relative values against the robots.txt URL.
func extractRecognyzeURL(robotsBody string, robotsURL string) string {
	lines := strings.Split(robotsBody, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if len(line) < len("recognyze:") {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "recognyze:") {
			continue
		}
		value := strings.TrimSpace(line[len("recognyze:"):])
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil {
			continue
		}
		if u.IsAbs() {
			return u.String()
		}
		base, err := url.Parse(robotsURL)
		if err != nil {
			continue
		}
		return base.ResolveReference(u).String()
	}
	return ""
}

// parseRecognyzePaths parses recognyze.txt into a deduplicated canonical path set.
// It accepts plain paths, wildcard suffixes, URL entries, and enriched bracket form.
func parseRecognyzePaths(content string) []string {
	lines := strings.Split(content, "\n")
	paths := make([]string, 0, len(lines))
	seen := map[string]struct{}{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Support enriched recognyze format:
		// [/path] name="..." id=... changed=...
		if strings.HasPrefix(line, "[") {
			if end := strings.Index(line, "]"); end > 1 {
				line = strings.TrimSpace(line[1:end])
			}
		}
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "/") && !strings.HasPrefix(strings.ToLower(line), "http://") && !strings.HasPrefix(strings.ToLower(line), "https://") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "http://") || strings.HasPrefix(strings.ToLower(line), "https://") {
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			line = u.Path
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		paths = append(paths, line)
	}
	return paths
}

// matchesProtectedPath evaluates a request path against exact and prefix-wildcard
// protected entries.
func matchesProtectedPath(path string, protectedPaths []string) bool {
	for _, candidate := range protectedPaths {
		if strings.HasSuffix(candidate, "*") {
			prefix := strings.TrimSuffix(candidate, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == candidate {
			return true
		}
	}
	return false
}
