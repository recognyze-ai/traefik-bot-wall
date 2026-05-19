package traefik_bot_wall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewClassifierUsesDefaultFileWhenNoBotRulesFile(t *testing.T) {
	cfg, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:   "",
		RulesCacheFile: filepath.Join(t.TempDir(), "missing-rules-cache.json"),
		BotRulesURL:    "disabled",
	})
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	classifier, err := NewClassifier(cfg)
	if err != nil {
		t.Fatalf("unexpected classifier error: %v", err)
	}
	if classifier.RuleSource() != "default_file" {
		t.Fatalf("expected default_file source, got: %s", classifier.RuleSource())
	}

	classification := classifier.Classify("Googlebot/2.1")
	if !classification.Matched {
		t.Fatalf("expected default rules file to match Googlebot")
	}
}

func TestNewClassifierPrefersLocalFileWhenRemoteNotConfigured(t *testing.T) {
	tempDir := t.TempDir()
	localFile := filepath.Join(tempDir, "local-rules.json")
	cacheFile := filepath.Join(tempDir, "cache-rules.json")

	localRules := `{"ua_patterns":[{"category":"LocalAgent","patterns":["local-agent"]}]}`
	cacheRules := `{"ua_patterns":[{"category":"CacheAgent","patterns":["cache-agent"]}]}`
	if err := os.WriteFile(localFile, []byte(localRules), 0o644); err != nil {
		t.Fatalf("write local rules: %v", err)
	}
	if err := os.WriteFile(cacheFile, []byte(cacheRules), 0o644); err != nil {
		t.Fatalf("write cache rules: %v", err)
	}

	cfg, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:   localFile,
		RulesCacheFile: cacheFile,
		BotRulesURL:    "disabled",
	})
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	classifier, err := NewClassifier(cfg)
	if err != nil {
		t.Fatalf("unexpected classifier error: %v", err)
	}
	if classifier.RuleSource() != "local_file" {
		t.Fatalf("expected local_file source, got: %s", classifier.RuleSource())
	}
	if !classifier.Classify("local-agent").Matched {
		t.Fatalf("expected local rules to classify local-agent")
	}
	if classifier.Classify("cache-agent").Matched {
		t.Fatalf("did not expect cache rules to apply when remote is disabled")
	}
}

func TestNewClassifierUsesRemoteCacheWhenRemoteEnabledAndCacheNewerThanLocal(t *testing.T) {
	tempDir := t.TempDir()
	localFile := filepath.Join(tempDir, "local-rules.json")
	cacheFile := filepath.Join(tempDir, "cache-rules.json")

	localRules := `{"ua_patterns":[{"category":"LocalAgent","patterns":["local-agent"]}]}`
	cacheRules := `{"ua_patterns":[{"category":"CacheAgent","patterns":["cache-agent"]}]}`
	if err := os.WriteFile(localFile, []byte(localRules), 0o644); err != nil {
		t.Fatalf("write local rules: %v", err)
	}
	if err := os.WriteFile(cacheFile, []byte(cacheRules), 0o644); err != nil {
		t.Fatalf("write cache rules: %v", err)
	}

	cfg, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:   localFile,
		RulesCacheFile: cacheFile,
		BotRulesURL:    "https://example.com/rules.json",
	})
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	classifier, err := NewClassifier(cfg)
	if err != nil {
		t.Fatalf("unexpected classifier error: %v", err)
	}
	if classifier.RuleSource() != "remote_cached_fallback" {
		t.Fatalf("expected remote_cached_fallback source, got: %s", classifier.RuleSource())
	}
	if !classifier.Classify("cache-agent").Matched {
		t.Fatalf("expected cached remote rules to classify cache-agent")
	}
}

func TestNewClassifierPrefersLocalFileWhenConfiguredEvenIfCacheIsNewer(t *testing.T) {
	tempDir := t.TempDir()
	localFile := filepath.Join(tempDir, "local-rules.json")
	cacheFile := filepath.Join(tempDir, "cache-rules.json")

	localRules := `{"ua_patterns":[{"category":"LocalAgent","patterns":["local-agent"]}]}`
	cacheRules := `{"ua_patterns":[{"category":"CacheAgent","patterns":["cache-agent"]}]}`
	if err := os.WriteFile(localFile, []byte(localRules), 0o644); err != nil {
		t.Fatalf("write local rules: %v", err)
	}
	if err := os.WriteFile(cacheFile, []byte(cacheRules), 0o644); err != nil {
		t.Fatalf("write cache rules: %v", err)
	}

	cfg, err := parseAndNormalizeConfig(&Config{
		BotRulesFile:            localFile,
		RulesCacheFile:          cacheFile,
		BotRulesURL:             "https://example.com/rules.json",
		PreferLocalBotRulesFile: true,
	})
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	classifier, err := NewClassifier(cfg)
	if err != nil {
		t.Fatalf("unexpected classifier error: %v", err)
	}
	if classifier.RuleSource() != "local_file" {
		t.Fatalf("expected local_file source, got: %s", classifier.RuleSource())
	}
	if !classifier.Classify("local-agent").Matched {
		t.Fatalf("expected local rules to classify local-agent")
	}
	if classifier.Classify("cache-agent").Matched {
		t.Fatalf("did not expect cache rules when preferLocalBotRulesFile=true")
	}
}
