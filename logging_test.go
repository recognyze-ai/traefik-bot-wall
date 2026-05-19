package traefik_bot_wall

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestEventLoggerWritesInlineMetadataHeader(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	logger := NewEventLogger(&parsedConfig{
		Config: Config{
			DecisionLogFile: logPath,
		},
		publisherLogsInterval: time.Minute,
	})

	req := httptest.NewRequest(http.MethodGet, "http://myapp.localhost/", nil)
	req.Header.Set("User-Agent", "test-ua")
	logger.Log(BuildAccessLogEvent(req, "10.0.0.1", 403, 100))

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed reading log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected metadata + event lines, got %d", len(lines))
	}

	var metadataEnvelope EventMetadataEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &metadataEnvelope); err != nil {
		t.Fatalf("first line is not metadata json: %v", err)
	}
	if metadataEnvelope.Metadata.Source.Name != "traefik" {
		t.Fatalf("unexpected metadata source: %s", metadataEnvelope.Metadata.Source.Name)
	}
	if !strings.Contains(metadataEnvelope.Metadata.Source.Details, "go=") {
		t.Fatalf("expected go version in metadata details: %s", metadataEnvelope.Metadata.Source.Details)
	}
	if !strings.Contains(metadataEnvelope.Metadata.Source.Details, "botwall=") {
		t.Fatalf("expected plugin version in metadata details: %s", metadataEnvelope.Metadata.Source.Details)
	}
	if metadataEnvelope.Metadata.ExportFormat != "standard_log_format" {
		t.Fatalf("unexpected export format: %s", metadataEnvelope.Metadata.ExportFormat)
	}
}

func TestEventLoggerShipAndTruncateClearsFileContent(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	var (
		shippedPayload     string
		shippedContentType string
		shippedAccept      string
		shippedAPIKey      string
		shippedMethod      string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shippedMethod = r.Method
		shippedContentType = r.Header.Get("Content-Type")
		shippedAccept = r.Header.Get("Accept")
		shippedAPIKey = r.Header.Get("X-API-KEY")
		body, _ := io.ReadAll(r.Body)
		shippedPayload = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	logger := NewEventLogger(&parsedConfig{
		Config: Config{
			DecisionLogFile:  logPath,
			PublisherLogsURL: server.URL,
			PublisherAPIKey:  "test-api-key",
		},
		publisherLogsInterval: time.Minute,
	})
	req := httptest.NewRequest(http.MethodGet, "http://myapp.localhost/", nil)
	logger.Log(BuildAccessLogEvent(req, "10.0.0.1", 200, 0))

	if err := logger.shipAndTruncateOnce(); err != nil {
		t.Fatalf("shipAndTruncateOnce failed: %v", err)
	}
	if strings.TrimSpace(shippedPayload) == "" {
		t.Fatalf("expected shipped payload")
	}
	if shippedMethod != http.MethodPost {
		t.Fatalf("expected POST, got: %s", shippedMethod)
	}
	if shippedContentType != "application/jsonl" {
		t.Fatalf("expected Content-Type application/jsonl, got: %q", shippedContentType)
	}
	if shippedAccept != "application/json" {
		t.Fatalf("expected Accept application/json, got: %q", shippedAccept)
	}
	if shippedAPIKey != "test-api-key" {
		t.Fatalf("expected X-API-KEY header to carry the configured key, got: %q", shippedAPIKey)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed reading log file after truncate: %v", err)
	}
	if strings.TrimSpace(string(content)) != "" {
		t.Fatalf("expected empty file after truncate, got: %q", string(content))
	}
}

func TestEventLoggerShipFailsOnJSONErrorField(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":true,"message":"rejected"}`))
	}))
	defer server.Close()

	logger := NewEventLogger(&parsedConfig{
		Config: Config{
			DecisionLogFile:  logPath,
			PublisherLogsURL: server.URL,
		},
		publisherLogsInterval: time.Minute,
	})
	req := httptest.NewRequest(http.MethodGet, "http://myapp.localhost/", nil)
	logger.Log(BuildAccessLogEvent(req, "10.0.0.1", 200, 0))

	if err := logger.shipAndTruncateOnce(); err == nil {
		t.Fatal("expected ship to fail when JSON error field is true")
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed reading log file: %v", err)
	}
	if strings.TrimSpace(string(content)) == "" {
		t.Fatal("expected log file to be preserved when ship fails")
	}
}

func TestResolvePluginVersion(t *testing.T) {
	tests := []struct {
		name     string
		build    *debug.BuildInfo
		expected string
		ok       bool
	}{
		{
			name: "main module plugin version",
			build: &debug.BuildInfo{
				Main: debug.Module{
					Path:    pluginModulePath,
					Version: "v1.2.3",
				},
			},
			expected: "1.2.3",
			ok:       true,
		},
		{
			name: "dependency plugin version",
			build: &debug.BuildInfo{
				Main: debug.Module{Path: "github.com/traefik/traefik/v3", Version: "v3.6.12"},
				Deps: []*debug.Module{
					{Path: pluginModulePath, Version: "v1.4.0"},
				},
			},
			expected: "1.4.0",
			ok:       true,
		},
		{
			name: "ignores non-plugin main module",
			build: &debug.BuildInfo{
				Main: debug.Module{Path: "github.com/traefik/traefik/v3", Version: "v3.6.12"},
			},
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resolvePluginVersion(tt.build)
			if ok != tt.ok {
				t.Fatalf("expected ok=%v, got %v", tt.ok, ok)
			}
			if got != tt.expected {
				t.Fatalf("expected version=%q, got %q", tt.expected, got)
			}
		})
	}
}
