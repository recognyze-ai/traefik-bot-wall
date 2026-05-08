package botwall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// AccessLogEvent is one JSONL record (excluding the file metadata line) in Apache-style
// "combined" form, matching the standard_log_format consumer shape.
type AccessLogEvent struct {
	RemoteHost    string `json:"remote_host"`
	RemoteLogname string `json:"remote_logname"`
	RemoteUser    string `json:"remote_user"`
	RequestTime   string `json:"request_time"`
	RequestLine   string `json:"request_line"`
	RequestMethod string `json:"request_method"`
	RequestPath   string `json:"request_path"`
	RequestProto  string `json:"request_protocol"`
	Status        int    `json:"status"`
	BytesSent     int    `json:"bytes_sent"`
	Referer       string `json:"referer"`
	UserAgent     string `json:"user_agent"`
	OriginalLine  string `json:"original_line"`
}

// BuildAccessLogEvent assembles a single line from the incoming request, response status, and body size.
// remoteLogname is the client address (e.g. resolved IP). remoteUser is "- -", matching the ident/auth placeholders in a combined log line.
func BuildAccessLogEvent(req *http.Request, clientIP string, status, bytesSent int) AccessLogEvent {
	if req == nil {
		req = &http.Request{}
	}
	now := time.Now().UTC()
	remoteHost := strings.TrimSpace(req.Host)
	if remoteHost == "" {
		remoteHost = "-"
	}
	rl := strings.TrimSpace(clientIP)
	if rl == "" {
		rl = "-"
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	requestTarget := req.RequestURI
	if requestTarget == "" && req.URL != nil {
		requestTarget = req.URL.RequestURI()
	}
	if requestTarget == "" {
		requestTarget = "/"
	}
	var pathStr string
	if req.URL != nil {
		if p := req.URL.Path; p != "" {
			pathStr = p
		} else {
			if i := strings.IndexByte(requestTarget, '?'); i >= 0 {
				pathStr = requestTarget[:i]
			} else {
				pathStr = requestTarget
			}
		}
	} else if i := strings.IndexByte(requestTarget, '?'); i >= 0 {
		pathStr = requestTarget[:i]
	} else {
		pathStr = requestTarget
	}
	if pathStr == "" {
		pathStr = "/"
	}
	proto := req.Proto
	if strings.TrimSpace(proto) == "" {
		proto = "HTTP/1.1"
	}
	reqLine := method + " " + requestTarget + " " + proto
	ua := sanitizeUserAgent(req.UserAgent())
	referer := strings.TrimSpace(req.Referer())
	if referer == "" {
		referer = "-"
	}

	origRef := referer
	origUA := ua
	if origRef == "" {
		origRef = "-"
	}
	if origUA == "" {
		origUA = "-"
	}

	return AccessLogEvent{
		RemoteHost:    remoteHost,
		RemoteLogname: rl,
		RemoteUser:    "- -",
		RequestTime:   now.Format("2006-01-02T15:04:05-07:00"),
		RequestLine:   reqLine,
		RequestMethod: method,
		RequestPath:   pathStr,
		RequestProto:  proto,
		Status:        status,
		BytesSent:     bytesSent,
		Referer:       referer,
		UserAgent:     ua,
		OriginalLine: fmt.Sprintf(
			`%s %s - - [%s] %q %d %d %q %q`,
			remoteHost, rl, now.Format("02/Jan/2006:15:04:05 -0700"), reqLine, status, bytesSent, origRef, origUA,
		),
	}
}

type EventLogger struct {
	path                  string
	publisherLogsURL      string
	publisherAPIKey       string
	publisherLogsInterval time.Duration
	shipHTTPClient        *http.Client
	mu                    sync.Mutex
	metadataApplied       bool // under mu; cleared after truncate so header logic runs again
	metadataErr           error
	lastShipAt            time.Time
}

const maxUserAgentBytes = 512
const defaultPluginVersion = "1.0.0"
const pluginModulePath = "github.com/recognyze-ai/bot-wall"

func sanitizeUserAgent(userAgent string) string {
	if strings.TrimSpace(userAgent) == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(userAgent))
	for _, r := range userAgent {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	sanitized := b.String()
	if len(sanitized) <= maxUserAgentBytes {
		return sanitized
	}

	sanitized = sanitized[:maxUserAgentBytes]
	for !utf8.ValidString(sanitized) && len(sanitized) > 0 {
		sanitized = sanitized[:len(sanitized)-1]
	}
	return sanitized
}

func NewEventLogger(cfg *parsedConfig) *EventLogger {
	if cfg == nil || strings.TrimSpace(cfg.DecisionLogFile) == "" {
		return &EventLogger{}
	}

	return &EventLogger{
		path:                  cfg.DecisionLogFile,
		publisherLogsURL:      strings.TrimSpace(cfg.PublisherLogsURL),
		publisherAPIKey:       strings.TrimSpace(cfg.PublisherAPIKey),
		publisherLogsInterval: cfg.publisherLogsInterval,
		shipHTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (l *EventLogger) Log(event AccessLogEvent) {
	if l == nil || l.path == "" {
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}

	l.mu.Lock()
	shouldShip := false
	defer func() {
		l.mu.Unlock()
		if shouldShip {
			go func() {
				if err := l.shipAndTruncateOnce(); err != nil {
					log.Printf("[botwall] event ship on-write failed: %v", err)
				}
			}()
		}
	}()

	if err := l.ensureMetadataHeaderLocked(); err != nil {
		log.Printf("[botwall] create metadata header failed: %v", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("[botwall] open decision log failed: %v", err)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("[botwall] close decision log failed: %v", err)
		}
	}()

	if _, err := f.Write(append(body, '\n')); err != nil {
		log.Printf("[botwall] append decision log failed: %v", err)
	}

	if l.publisherLogsURL != "" && l.publisherLogsInterval > 0 {
		now := time.Now()
		if l.lastShipAt.IsZero() || now.Sub(l.lastShipAt) >= l.publisherLogsInterval {
			l.lastShipAt = now
			shouldShip = true
		}
	}
}

type EventMetadata struct {
	ExportFormat   string `json:"export_format"`
	ExportDate     string `json:"export_date"`
	ExportTimezone string `json:"export_timezone"`
	TotalRecords   int    `json:"total_records"`
	FiltersApplied struct {
		BotTypeFilter   string `json:"bot_type_filter"`
		PostTitleSearch string `json:"post_title_search"`
		IPAddressSearch string `json:"ip_address_search"`
	} `json:"filters_applied"`
	FormatVersion string `json:"format_version"`
	Description   string `json:"description"`
	Source        struct {
		Name    string `json:"name"`
		Details string `json:"details"`
	} `json:"source"`
}

type EventMetadataEnvelope struct {
	Metadata EventMetadata `json:"metadata"`
}

func (l *EventLogger) StartShippingLoop() {
	if l == nil || l.path == "" || l.publisherLogsURL == "" || l.publisherLogsInterval <= 0 {
		return
	}
	log.Printf("[botwall] publisher logs ship loop enabled path=%s url=%s interval=%s", l.path, l.publisherLogsURL, l.publisherLogsInterval)
	go func() {
		ticker := time.NewTicker(l.publisherLogsInterval)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("[botwall] publisher logs ship tick starting")
			if err := l.shipAndTruncateOnce(); err != nil {
				log.Printf("[botwall] publisher logs ship tick failed: %v", err)
				continue
			}
			l.mu.Lock()
			l.lastShipAt = time.Now()
			l.mu.Unlock()
			log.Printf("[botwall] publisher logs ship tick succeeded")
		}
	}()
}

func (l *EventLogger) shipAndTruncateOnce() error {
	if l == nil || l.path == "" || l.publisherLogsURL == "" {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.ensureMetadataHeaderLocked(); err != nil {
		return err
	}

	body, firstLine, err := l.readLogPayloadLocked()
	if err != nil {
		return err
	}
	if len(body) == 0 || len(firstLine) == 0 {
		return nil
	}

	req, err := http.NewRequest(http.MethodPost, l.publisherLogsURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/jsonl")
	req.Header.Set("Accept", "application/json")
	if l.publisherAPIKey != "" {
		req.Header.Set("X-API-KEY", l.publisherAPIKey)
	}
	resp, err := l.shipHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("publisher logs endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	// Keep the file but clear all contents after a successful ship.
	// Metadata will be re-created lazily on the next event write.
	if err := os.Truncate(l.path, 0); err != nil {
		return err
	}
	l.metadataApplied = false
	l.metadataErr = nil
	return nil
}

func (l *EventLogger) readLogPayloadLocked() ([]byte, []byte, error) {
	content, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	lines := bytes.Split(content, []byte("\n"))
	if len(lines) == 0 || len(bytes.TrimSpace(lines[0])) == 0 {
		return nil, nil, nil
	}
	firstLine := bytes.TrimSpace(lines[0])
	if len(lines) <= 1 {
		return nil, firstLine, nil
	}

	var payload bytes.Buffer
	payload.Write(firstLine)
	payload.WriteByte('\n')
	wroteEvent := false
	for _, line := range lines[1:] {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		wroteEvent = true
		payload.Write(trimmed)
		payload.WriteByte('\n')
	}
	if !wroteEvent {
		return nil, firstLine, nil
	}
	return payload.Bytes(), firstLine, nil
}

func (l *EventLogger) ensureMetadataHeaderLocked() error {
	if l.metadataApplied {
		return l.metadataErr
	}
	defer func() { l.metadataApplied = true }()

	firstLine, err := l.readFirstLine()
	if err != nil {
		l.metadataErr = err
		return l.metadataErr
	}
	header, err := l.buildMetadataLine()
	if err != nil {
		l.metadataErr = err
		return l.metadataErr
	}
	if len(firstLine) == 0 {
		l.metadataErr = os.WriteFile(l.path, append(header, '\n'), 0o600)
		return l.metadataErr
	}
	if isMetadataLine(firstLine) {
		return l.metadataErr
	}
	content, err := os.ReadFile(l.path)
	if err != nil {
		l.metadataErr = err
		return l.metadataErr
	}
	var migrated bytes.Buffer
	migrated.Write(header)
	migrated.WriteByte('\n')
	migrated.Write(content)
	l.metadataErr = os.WriteFile(l.path, migrated.Bytes(), 0o600)
	return l.metadataErr
}

func (l *EventLogger) readFirstLine() ([]byte, error) {
	content, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	idx := bytes.IndexByte(content, '\n')
	if idx == -1 {
		return bytes.TrimSpace(content), nil
	}
	return bytes.TrimSpace(content[:idx]), nil
}

func (l *EventLogger) buildMetadataLine() ([]byte, error) {
	metadata := EventMetadata{
		ExportFormat:   "standard_log_format",
		ExportDate:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		ExportTimezone: "+00:00",
		TotalRecords:   0,
		FormatVersion:  "1.0",
		Description:    "Access logs exported in standard log format",
	}
	metadata.Source.Name = "traefik"
	metadata.Source.Details = fmt.Sprintf("go=%s, botwall=%s", goVersion(), pluginVersion())

	return json.Marshal(EventMetadataEnvelope{Metadata: metadata})
}

func goVersion() string {
	version := strings.TrimSpace(runtime.Version())
	if version == "" {
		return "unknown"
	}
	return version
}

func pluginVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		if v, ok := resolvePluginVersion(bi); ok {
			return v
		}
	}
	return defaultPluginVersion
}

func resolvePluginVersion(bi *debug.BuildInfo) (string, bool) {
	if bi == nil {
		return "", false
	}
	if strings.TrimSpace(bi.Main.Path) == pluginModulePath {
		if v, ok := normalizeBuildVersion(bi.Main.Version); ok {
			return v, true
		}
	}
	for _, dep := range bi.Deps {
		if dep == nil || strings.TrimSpace(dep.Path) != pluginModulePath {
			continue
		}
		if v, ok := normalizeBuildVersion(dep.Version); ok {
			return v, true
		}
	}
	return "", false
}

func normalizeBuildVersion(version string) (string, bool) {
	v := strings.TrimSpace(version)
	if v == "" || v == "(devel)" {
		return "", false
	}
	return strings.TrimPrefix(v, "v"), true
}

func isMetadataLine(line []byte) bool {
	var envelope EventMetadataEnvelope
	if err := json.Unmarshal(line, &envelope); err == nil {
		return strings.TrimSpace(envelope.Metadata.Source.Name) != "" && strings.TrimSpace(envelope.Metadata.FormatVersion) != ""
	}

	var metadata EventMetadata
	if err := json.Unmarshal(line, &metadata); err != nil {
		return false
	}
	return strings.TrimSpace(metadata.Source.Name) != "" && strings.TrimSpace(metadata.FormatVersion) != ""
}
