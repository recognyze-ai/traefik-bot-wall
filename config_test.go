package traefik_bot_wall

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndNormalizeConfigRejectsSameBotRulesAndRulesCachePaths(t *testing.T) {
	samePath := filepath.Join(t.TempDir(), "rules.json")
	if _, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:   samePath + string(filepath.Separator) + ".",
		RulesCacheFile: samePath,
	}); err == nil {
		t.Fatalf("expected error when botRulesFile and rulesCacheFile normalize to same path")
	}
}

func TestParseAndNormalizeConfigAllowsDistinctBotRulesAndRulesCachePaths(t *testing.T) {
	dir := t.TempDir()
	_, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:   filepath.Join(dir, "a.json"),
		RulesCacheFile: filepath.Join(dir, "b.json"),
	})
	if err != nil {
		t.Fatalf("unexpected error for distinct paths: %v", err)
	}
}

func TestParseAndNormalizeConfigDefaults(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.cacheTTL.String() != "24h0m0s" {
		t.Fatalf("unexpected cache ttl: %s", cfg.cacheTTL)
	}
	if cfg.refreshBeforeExpiry.String() != "1h0m0s" {
		t.Fatalf("unexpected refresh before expiry: %s", cfg.refreshBeforeExpiry)
	}
	if cfg.BotRulesFile != "" {
		t.Fatalf("expected empty default bot rules file, got: %s", cfg.BotRulesFile)
	}
	if cfg.BotRulesURL != DefaultBotRulesURL {
		t.Fatalf("expected default prod botRulesURL %q, got: %q", DefaultBotRulesURL, cfg.BotRulesURL)
	}
}

func TestParseAndNormalizeConfigRejectsInvalidRefreshWindow(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		CacheTTL:            "24h",
		RefreshBeforeExpiry: "24h",
	})
	if err == nil {
		t.Fatalf("expected error for invalid refresh window")
	}
}

func TestParseAndNormalizeConfigRejectsInsecureBotRulesURLByDefault(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		BotRulesURL: "http://example.com/rules.json",
	})
	if err == nil {
		t.Fatalf("expected error for insecure botRulesURL")
	}
}

func TestParseAndNormalizeConfigAllowsInsecureBotRulesURLWhenExplicitlyEnabled(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		BotRulesURL:              "http://example.com/rules.json",
		AllowInsecureBotRulesURL: true,
	})
	if err != nil {
		t.Fatalf("unexpected error when insecure botRulesURL override is enabled: %v", err)
	}
}

func TestParseAndNormalizeConfigRejectsInvalidPublisherLogsInterval(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		PublisherLogsInterval: "0s",
	})
	if err == nil {
		t.Fatalf("expected error for invalid publisherLogsInterval")
	}
}

func TestParseAndNormalizeConfigRejectsInsecurePublisherLogsURLByDefault(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL: "http://example.com/api/v1/publisher/logs/",
		PublisherAPIKey:  "test-key",
	})
	if err == nil {
		t.Fatalf("expected error for insecure publisherLogsURL")
	}
}

func TestParseAndNormalizeConfigRequiresPublisherAPIKeyWhenURLSet(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL: "https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
	})
	if err == nil {
		t.Fatalf("expected error when publisherLogsURL is set without publisherAPIKey")
	}
	if !strings.Contains(err.Error(), "publisherAPIKey") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestParseAndNormalizeConfigAcceptsPublisherLogsURLWithKey(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{
		PublisherLogsURL: "https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
		PublisherAPIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PublisherLogsURL == "" || cfg.PublisherAPIKey == "" {
		t.Fatalf("publisher fields not retained on parsedConfig: %+v", cfg)
	}
}

func TestParseAndNormalizeConfigRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	_, err := parseAndNormalizeConfig(&Config{
		TrustedProxyCIDRs: []string{"not-a-valid-cidr"},
	})
	if err == nil {
		t.Fatalf("expected error for invalid trustedProxyCIDRs")
	}
}

func TestParseAndNormalizeConfigBotRulesURLDevAndDisabled(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{
		BotRulesURL: "https://portal.dev.recognyze.ai/api/v1/bot-rules",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BotRulesURL != "https://portal.dev.recognyze.ai/api/v1/bot-rules" {
		t.Fatalf("unexpected: %q", cfg.BotRulesURL)
	}

	cfg2, err := parseAndNormalizeConfig(&Config{BotRulesURL: "disabled"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.BotRulesURL != "" {
		t.Fatalf("disabled should clear URL, got %q", cfg2.BotRulesURL)
	}
}
