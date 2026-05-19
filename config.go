package traefik_bot_wall

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCacheTTL              = "24h"
	defaultRefreshBeforeExpiry   = "1h"
	defaultRefreshJitter         = "5m"
	defaultRulesRefresh          = "6h"
	defaultPublisherLogsInterval = "5m"

	defaultRulesCache   = "/tmp/botwall_rules_cache.json"
	defaultIndexCache   = "/tmp/botwall_recognyze_cache.json"
	defaultEventLogFile = "/var/log/traefik/botwall_events.jsonl"

	// DefaultBotRulesURL is the production Recognyze portal Bot Rules API (JSON with optional bot_rules wrapper).
	DefaultBotRulesURL = "https://portal.recognyze.ai/api/v1/bot-rules"
)

type Config struct {
	RecognyzeURL string `json:"recognyzeURL,omitempty" yaml:"recognyzeURL,omitempty"`
	RobotsTxtURL string `json:"robotsTxtURL,omitempty" yaml:"robotsTxtURL,omitempty"`

	CacheTTL            string `json:"cacheTTL,omitempty" yaml:"cacheTTL,omitempty"`
	RefreshBeforeExpiry string `json:"refreshBeforeExpiry,omitempty" yaml:"refreshBeforeExpiry,omitempty"`
	RefreshJitter       string `json:"refreshJitter,omitempty" yaml:"refreshJitter,omitempty"`
	CacheFile           string `json:"cacheFile,omitempty" yaml:"cacheFile,omitempty"`

	BotRulesFile string `json:"botRulesFile,omitempty" yaml:"botRulesFile,omitempty"`
	// BotRulesURL pulls Bot Rules JSON (ua_patterns, ipVerification, â€¦). Defaults to prod (DefaultBotRulesURL).
	// Example dev: https://portal.dev.recognyze.ai/api/v1/bot-rules
	// Set to "disabled" (or "none"/"off") to disable remote sync and use only default/local/cache files.
	BotRulesURL              string `json:"botRulesURL,omitempty" yaml:"botRulesURL,omitempty"`
	PreferLocalBotRulesFile  bool   `json:"preferLocalBotRulesFile,omitempty" yaml:"preferLocalBotRulesFile,omitempty"`
	RulesRefresh             string `json:"rulesRefreshInterval,omitempty" yaml:"rulesRefreshInterval,omitempty"`
	RulesMergeStrategy       string `json:"rulesMergeStrategy,omitempty" yaml:"rulesMergeStrategy,omitempty"`
	RulesCacheFile           string `json:"rulesCacheFile,omitempty" yaml:"rulesCacheFile,omitempty"`
	AllowInsecureBotRulesURL bool   `json:"allowInsecureBotRulesURL,omitempty" yaml:"allowInsecureBotRulesURL,omitempty"`

	// TrustedProxyCIDRs lists trusted reverse-proxy / edge networks (immediate peer IP must fall in one of these to honor
	// CF-Connecting-IP, X-Forwarded-For, X-Real-IP). Empty list preserves legacy behavior (headers used; trust flag false).
	TrustedProxyCIDRs []string `json:"trustedProxyCIDRs,omitempty" yaml:"trustedProxyCIDRs,omitempty"`

	Policy PolicyConfig `json:"policy,omitempty" yaml:"policy,omitempty"`

	// EnableIPSoftmax enables UA+IP softmax attribution (same strategy as recognyze WordPress plugin when ipVerification is present).
	EnableIPSoftmax bool    `json:"enableIPSoftmax,omitempty" yaml:"enableIPSoftmax,omitempty"`
	SoftmaxAlpha    float64 `json:"softmaxAlpha,omitempty" yaml:"softmaxAlpha,omitempty"`
	SoftmaxBeta     float64 `json:"softmaxBeta,omitempty" yaml:"softmaxBeta,omitempty"`

	DecisionLogFile string `json:"decisionLogFile,omitempty" yaml:"decisionLogFile,omitempty"`
	// PublisherLogsURL is the absolute URL of the Recognyze publisher logs ingest endpoint
	// (production: https://portal.recognyze.ai/api/v1/publisher/logs/, dev: https://portal.dev.recognyze.ai/api/v1/publisher/logs/).
	// When set, the plugin POSTs accumulated decision events to this URL as application/jsonl,
	// authenticated with the X-API-KEY header. Setting this field requires PublisherAPIKey.
	PublisherLogsURL string `json:"publisherLogsURL,omitempty" yaml:"publisherLogsURL,omitempty"`
	// PublisherAPIKey is the plaintext API key sent in the X-API-KEY header to PublisherLogsURL.
	// Required when PublisherLogsURL is set; protect the surrounding YAML file with filesystem permissions.
	PublisherAPIKey       string `json:"publisherAPIKey,omitempty"       yaml:"publisherAPIKey,omitempty"`
	PublisherLogsInterval string `json:"publisherLogsInterval,omitempty" yaml:"publisherLogsInterval,omitempty"`
	DenyInfoURL           string `json:"denyInfoURL,omitempty" yaml:"denyInfoURL,omitempty"`
}

type parsedConfig struct {
	Config
	trustedProxyNets      []*net.IPNet
	cacheTTL              time.Duration
	refreshBeforeExpiry   time.Duration
	refreshJitter         time.Duration
	rulesRefresh          time.Duration
	publisherLogsInterval time.Duration
}

func CreateConfig() *Config {
	return &Config{
		CacheTTL:              defaultCacheTTL,
		RefreshBeforeExpiry:   defaultRefreshBeforeExpiry,
		RefreshJitter:         defaultRefreshJitter,
		CacheFile:             defaultIndexCache,
		RulesRefresh:          defaultRulesRefresh,
		RulesMergeStrategy:    "replace-with-remote-on-success",
		RulesCacheFile:        defaultRulesCache,
		DecisionLogFile:       defaultEventLogFile,
		PublisherLogsInterval: defaultPublisherLogsInterval,
		Policy: PolicyConfig{
			GlobalPolicy: "deny",
			Rules:        map[string]string{},
			BotOverrides: map[string]string{},
		},
		SoftmaxAlpha: 4,
		SoftmaxBeta:  4,
	}
}

func parseAndNormalizeConfig(input *Config) (*parsedConfig, error) {
	cfg := CreateConfig()
	if input != nil {
		*cfg = *input
	}

	if strings.TrimSpace(cfg.CacheTTL) == "" {
		cfg.CacheTTL = defaultCacheTTL
	}
	if strings.TrimSpace(cfg.RefreshBeforeExpiry) == "" {
		cfg.RefreshBeforeExpiry = defaultRefreshBeforeExpiry
	}
	if strings.TrimSpace(cfg.RefreshJitter) == "" {
		cfg.RefreshJitter = defaultRefreshJitter
	}
	if strings.TrimSpace(cfg.RulesRefresh) == "" {
		cfg.RulesRefresh = defaultRulesRefresh
	}
	if strings.TrimSpace(cfg.CacheFile) == "" {
		cfg.CacheFile = defaultIndexCache
	}
	if strings.TrimSpace(cfg.RulesCacheFile) == "" {
		cfg.RulesCacheFile = defaultRulesCache
	}
	if strings.TrimSpace(cfg.DecisionLogFile) == "" {
		cfg.DecisionLogFile = defaultEventLogFile
	}
	if strings.TrimSpace(cfg.RulesMergeStrategy) == "" {
		cfg.RulesMergeStrategy = "replace-with-remote-on-success"
	}
	if strings.TrimSpace(cfg.PublisherLogsInterval) == "" {
		cfg.PublisherLogsInterval = defaultPublisherLogsInterval
	}
	if cfg.SoftmaxAlpha <= 0 {
		cfg.SoftmaxAlpha = 4
	}
	if cfg.SoftmaxBeta <= 0 {
		cfg.SoftmaxBeta = 4
	}

	normalizeBotRulesURL(cfg)

	if bot := strings.TrimSpace(cfg.BotRulesFile); bot != "" {
		cache := strings.TrimSpace(cfg.RulesCacheFile)
		if filepath.Clean(bot) == filepath.Clean(cache) {
			return nil, fmt.Errorf(
				"botRulesFile and rulesCacheFile must differ (same path after filepath.Clean: %s)",
				filepath.Clean(bot),
			)
		}
	}

	cacheTTL, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid cacheTTL: %w", err)
	}
	refreshBefore, err := time.ParseDuration(cfg.RefreshBeforeExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid refreshBeforeExpiry: %w", err)
	}
	refreshJitter, err := time.ParseDuration(cfg.RefreshJitter)
	if err != nil {
		return nil, fmt.Errorf("invalid refreshJitter: %w", err)
	}
	rulesRefresh, err := time.ParseDuration(cfg.RulesRefresh)
	if err != nil {
		return nil, fmt.Errorf("invalid rulesRefreshInterval: %w", err)
	}
	publisherLogsInterval, err := time.ParseDuration(cfg.PublisherLogsInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid publisherLogsInterval: %w", err)
	}
	if publisherLogsInterval <= 0 {
		return nil, fmt.Errorf("publisherLogsInterval must be greater than 0")
	}
	if refreshBefore >= cacheTTL {
		return nil, fmt.Errorf("refreshBeforeExpiry must be lower than cacheTTL")
	}
	if raw := strings.TrimSpace(cfg.BotRulesURL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return nil, fmt.Errorf("botRulesURL must be an absolute URL")
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
			// secure default
		case "http":
			if !cfg.AllowInsecureBotRulesURL {
				return nil, fmt.Errorf("botRulesURL must use https unless allowInsecureBotRulesURL=true (dev only)")
			}
		default:
			return nil, fmt.Errorf("botRulesURL must use http or https")
		}
	}
	if raw := strings.TrimSpace(cfg.PublisherLogsURL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return nil, fmt.Errorf("publisherLogsURL must be an absolute URL")
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
			// secure default
		case "http":
			if !cfg.AllowInsecureBotRulesURL {
				return nil, fmt.Errorf("publisherLogsURL must use https unless allowInsecureBotRulesURL=true (dev only)")
			}
		default:
			return nil, fmt.Errorf("publisherLogsURL must use http or https")
		}
		if strings.TrimSpace(cfg.PublisherAPIKey) == "" {
			return nil, fmt.Errorf("publisherAPIKey is required when publisherLogsURL is set")
		}
	}

	cfg.Policy.Normalize()

	nets, err := parseTrustedProxyNetworks(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &parsedConfig{
		Config:                *cfg,
		trustedProxyNets:      nets,
		cacheTTL:              cacheTTL,
		refreshBeforeExpiry:   refreshBefore,
		refreshJitter:         refreshJitter,
		rulesRefresh:          rulesRefresh,
		publisherLogsInterval: publisherLogsInterval,
	}, nil
}

// normalizeBotRulesURL sets the production portal API when botRulesURL is omitted, and reserves
// "disabled" / "none" / "off" to turn off remote fetch (local/default rules only).
func normalizeBotRulesURL(cfg *Config) {
	raw := strings.TrimSpace(cfg.BotRulesURL)
	if raw == "" {
		cfg.BotRulesURL = DefaultBotRulesURL
		return
	}
	switch strings.ToLower(raw) {
	case "disabled", "none", "off":
		cfg.BotRulesURL = ""
	}
}
