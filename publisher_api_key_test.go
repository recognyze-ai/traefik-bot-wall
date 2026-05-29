package traefik_bot_wall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolvePublisherAPIBaseURL(t *testing.T) {
	base, err := resolvePublisherAPIBaseURL(
		"https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://portal.dev.recognyze.ai/api/v1" {
		t.Fatalf("unexpected base: %q", base)
	}

	override, err := resolvePublisherAPIBaseURL("https://ignored.example/logs/", "https://custom.example/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	if override != "https://custom.example/api/v1" {
		t.Fatalf("unexpected override: %q", override)
	}
}

func TestIsRotationDue(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	expSoon := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	expLater := now.Add(20 * 24 * time.Hour).Format(time.RFC3339)

	if !IsRotationDue(expSoon, 14, now) {
		t.Fatal("expected rotation due within 14-day buffer")
	}
	if IsRotationDue(expLater, 14, now) {
		t.Fatal("expected rotation not due yet")
	}
}

func TestSecretPrefersStateFileOverBootstrap(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "key_state.json")
	st := publisherKeyState{
		Secret:     "sk_STATE_fromfile_secretpart",
		KeyID:      "sk_STATE",
		Expiration: time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	raw, err := encodePublisherKeyStateFile(st, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL:               "https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
		PublisherAPIKey:                "sk_BOOTSTRAP_secretpart",
		PublisherAPIKeyStateFile:       statePath,
		PublisherAPIKeyRotationEnabled: ptrBool(false),
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewPublisherKeyManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Secret(); got != st.Secret {
		t.Fatalf("expected state secret, got %q", got)
	}
}

func TestEncryptedStateRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st := publisherKeyState{
		Secret: "sk_TEST_abcdef1234567890",
		KeyID:  "sk_TEST",
	}
	raw, err := encodePublisherKeyStateFile(st, true, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodePublisherKeyStateFile(raw, true, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != st.Secret {
		t.Fatalf("secret mismatch: %q", got.Secret)
	}
}

func TestProactiveRotateUpdatesState(t *testing.T) {
	var rotateCalls atomic.Int32
	var rotated atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api-keys/current"):
			w.Header().Set("Content-Type", "application/json")
			keyID := "sk_OLD"
			exp := "2026-05-25T00:00:00Z"
			if rotated.Load() {
				keyID = "sk_NEW"
				exp = time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
			}
			_, _ = w.Write([]byte(`{
				"status":"success",
				"key":{
					"key_id":"` + keyID + `",
					"name":"test",
					"status":"active",
					"creation_date":"2026-01-01T00:00:00Z",
					"expiration_date":"` + exp + `"
				}
			}`))
		case r.Method == http.MethodPut && r.URL.Query().Get("op") == "rotate":
			rotateCalls.Add(1)
			rotated.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"status":"success",
				"key_id":"sk_NEW",
				"secret":"sk_NEW_rotatedsecretpart",
				"revoked_key_id":"sk_OLD",
				"name":"test-rotated"
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "key_state.json")
	logsURL := api.URL + "/api/v1/publisher/logs/"

	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL:                  logsURL,
		PublisherAPIKey:                   "sk_OLD_secretpart",
		PublisherAPIKeyStateFile:          statePath,
		PublisherAPIKeyRotationBufferDays: 14,
		AllowInsecureBotRulesURL:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublisherAPIBaseURL = api.URL + "/api/v1"

	m, err := NewPublisherKeyManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshMetadata(); err != nil {
		t.Fatal(err)
	}
	if err := m.MaybeRotateProactive(); err != nil {
		t.Fatal(err)
	}
	if rotateCalls.Load() != 1 {
		t.Fatalf("expected 1 rotate call, got %d", rotateCalls.Load())
	}
	if m.Secret() != "sk_NEW_rotatedsecretpart" {
		t.Fatalf("unexpected secret after rotate: %q", maskAPISecret(m.Secret()))
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var file publisherKeyStateFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.KeyID != "sk_NEW" {
		t.Fatalf("expected sk_NEW in state, got %q", file.KeyID)
	}
}

func TestProactiveRotateSkippedWhenNotActive(t *testing.T) {
	var rotateCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"key":{
					"key_id":"sk_OLD",
					"status":"revoked",
					"expiration_date":"2026-05-20T00:00:00Z"
				}
			}`))
			return
		}
		if r.Method == http.MethodPut {
			rotateCalls.Add(1)
		}
	}))
	defer api.Close()

	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL:         api.URL + "/api/v1/publisher/logs/",
		PublisherAPIKey:          "sk_OLD_secret",
		PublisherAPIKeyStateFile: filepath.Join(t.TempDir(), "state.json"),
		AllowInsecureBotRulesURL: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublisherAPIBaseURL = api.URL + "/api/v1"

	m, err := NewPublisherKeyManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshMetadata(); err != nil {
		t.Fatal(err)
	}
	if err := m.MaybeRotateProactive(); err != nil {
		t.Fatal(err)
	}
	if rotateCalls.Load() != 0 {
		t.Fatalf("expected no rotate, got %d", rotateCalls.Load())
	}
}

func TestRotateFallsBackToCurrentOn404(t *testing.T) {
	var tried []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api-keys/current") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":{"key_id":"sk_NEW","status":"active","expiration_date":"2027-01-01T00:00:00Z"}}`))
			return
		}
		if r.Method == http.MethodPut {
			id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/publisher/api-keys/"), "/")
			tried = append(tried, id)
			if id == "sk_STORED" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"secret":"sk_NEW_secret","key_id":"sk_NEW"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	raw, _ := encodePublisherKeyStateFile(publisherKeyState{
		Secret:     "sk_BOOT_secret",
		KeyID:      "sk_STORED",
		Expiration: time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Status:     "active",
	}, false, nil)
	_ = os.WriteFile(statePath, raw, 0o600)

	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL:         api.URL + "/api/v1/publisher/logs/",
		PublisherAPIKey:          "sk_BOOT_secret",
		PublisherAPIKeyStateFile: statePath,
		AllowInsecureBotRulesURL: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublisherAPIBaseURL = api.URL + "/api/v1"

	m, err := NewPublisherKeyManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.rotate(); err != nil {
		t.Fatal(err)
	}
	if len(tried) < 2 || tried[0] != "sk_STORED" || tried[1] != "current" {
		t.Fatalf("unexpected rotate candidates: %v", tried)
	}
}

func TestRotationDisabledByExplicitConfig(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL:               "https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
		PublisherAPIKey:                "sk_test",
		PublisherAPIKeyRotationEnabled: ptrBool(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.publisherAPIKeyRotationEnabled {
		t.Fatal("expected rotation disabled")
	}
}

func TestRotationEnabledByDefaultWhenPublisherLogsURLSet(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL: "https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
		PublisherAPIKey:  "sk_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.publisherAPIKeyRotationEnabled {
		t.Fatal("expected rotation enabled by default")
	}
}

func TestEventLoggerShip403DoesNotTruncate(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	var accountCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/publisher/logs") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		accountCalls.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	falseVal := false
	cfg, err := parseAndNormalizeConfig(&Config{
		DecisionLogFile:                logPath,
		PublisherLogsURL:               server.URL + "/api/v1/publisher/logs/",
		PublisherAPIKey:                "sk_test_secret",
		PublisherAPIKeyRotationEnabled: &falseVal,
		AllowInsecureBotRulesURL:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublisherAPIBaseURL = server.URL + "/api/v1"

	m, err := NewPublisherKeyManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := NewEventLogger(cfg, m)
	req := httptest.NewRequest(http.MethodGet, "http://myapp.localhost/", nil)
	logger.Log(BuildAccessLogEvent(req, "10.0.0.1", 200, 0))

	if err := logger.shipAndTruncateOnce(); err == nil {
		t.Fatal("expected ship error on 403")
	}
	if accountCalls.Load() != 0 {
		t.Fatalf("expected no account API calls on ship failure, got %d", accountCalls.Load())
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(content)) == "" {
		t.Fatal("expected log file preserved on 403")
	}
}

func ptrBool(v bool) *bool {
	return &v
}
