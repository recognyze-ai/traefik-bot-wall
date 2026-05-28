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
	defaultPublisherLogsInterval         = "5m"
	defaultPublisherAPIKeyStateFile        = "/tmp/botwall_publisher_api_key.json"
	defaultPublisherAPIKeyRotationBuffer = 14
	defaultPublisherAPIMetadataSync        = "24h"

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

	// PublisherAPIKeyStateFile stores the live API secret and metadata after proactive rotation (YAML key is bootstrap only).
	PublisherAPIKeyStateFile string `json:"publisherAPIKeyStateFile,omitempty" yaml:"publisherAPIKeyStateFile,omitempty"`
	// PublisherAPIBaseURL overrides API base derived from publisherLogsURL (…/api/v1).
	PublisherAPIBaseURL string `json:"publisherAPIBaseURL,omitempty" yaml:"publisherAPIBaseURL,omitempty"`
	// PublisherAPIKeyRotationEnabled: nil omits → true when publisherLogsURL is set. false = manual key management.
	PublisherAPIKeyRotationEnabled *bool `json:"publisherAPIKeyRotationEnabled,omitempty" yaml:"publisherAPIKeyRotationEnabled,omitempty"`
	PublisherAPIKeyRotationBufferDays int `json:"publisherAPIKeyRotationBufferDays,omitempty" yaml:"publisherAPIKeyRotationBufferDays,omitempty"`
	PublisherAPIKeyMetadataSyncInterval string `json:"publisherAPIKeyMetadataSyncInterval,omitempty" yaml:"publisherAPIKeyMetadataSyncInterval,omitempty"`
	PublisherAPIKeyEncryptAtRest       *bool  `json:"publisherAPIKeyEncryptAtRest,omitempty" yaml:"publisherAPIKeyEncryptAtRest,omitempty"`
	PublisherAPIKeyEncryptionKeyFile   string `json:"publisherAPIKeyEncryptionKeyFile,omitempty" yaml:"publisherAPIKeyEncryptionKeyFile,omitempty"`

	DenyInfoURL string `json:"denyInfoURL,omitempty" yaml:"denyInfoURL,omitempty"`
}

type parsedConfig struct {
	Config
	trustedProxyNets                    []*net.IPNet
	cacheTTL                            time.Duration
	refreshBeforeExpiry                 time.Duration
	refreshJitter                       time.Duration
	rulesRefresh                        time.Duration
	publisherLogsInterval               time.Duration
	publisherAPIKeyRotationEnabled      bool
	publisherAPIKeyRotationBufferDays   int
	publisherAPIKeyMetadataSyncInterval time.Duration
	publisherAPIKeyEncryptAtRest        bool
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

func mergeConfigInput(input *Config) *Config {
	cfg := CreateConfig()
	if input != nil {
		*cfg = *input
	}
	return cfg
}

func applyConfigDefaults(cfg *Config) {
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
	if strings.TrimSpace(cfg.PublisherAPIKeyStateFile) == "" {
		cfg.PublisherAPIKeyStateFile = defaultPublisherAPIKeyStateFile
	}
	if cfg.PublisherAPIKeyRotationBufferDays <= 0 {
		cfg.PublisherAPIKeyRotationBufferDays = defaultPublisherAPIKeyRotationBuffer
	}
	if strings.TrimSpace(cfg.PublisherAPIKeyMetadataSyncInterval) == "" {
		cfg.PublisherAPIKeyMetadataSyncInterval = defaultPublisherAPIMetadataSync
	}
}

func resolvePublisherAPIKeyRotationEnabled(cfg *Config) bool {
	if cfg.PublisherAPIKeyRotationEnabled != nil {
		return *cfg.PublisherAPIKeyRotationEnabled
	}
	return strings.TrimSpace(cfg.PublisherLogsURL) != ""
}

func resolvePublisherAPIKeyEncryptAtRest(cfg *Config) bool {
	if cfg.PublisherAPIKeyEncryptAtRest != nil {
		return *cfg.PublisherAPIKeyEncryptAtRest
	}
	return false
}

func validateBotRulesFilePaths(cfg *Config) error {
	bot := strings.TrimSpace(cfg.BotRulesFile)
	if bot == "" {
		return nil
	}
	cache := strings.TrimSpace(cfg.RulesCacheFile)
	if filepath.Clean(bot) == filepath.Clean(cache) {
		return fmt.Errorf(
			"botRulesFile and rulesCacheFile must differ (same path after filepath.Clean: %s)",
			filepath.Clean(bot),
		)
	}
	return nil
}

type configDurations struct {
	cacheTTL                            time.Duration
	refreshBeforeExpiry                 time.Duration
	refreshJitter                       time.Duration
	rulesRefresh                        time.Duration
	publisherLogsInterval               time.Duration
	publisherAPIKeyMetadataSyncInterval time.Duration
}

func parseConfigDurations(cfg *Config) (configDurations, error) {
	var d configDurations
	var err error
	if d.cacheTTL, err = time.ParseDuration(cfg.CacheTTL); err != nil {
		return d, fmt.Errorf("invalid cacheTTL: %w", err)
	}
	if d.refreshBeforeExpiry, err = time.ParseDuration(cfg.RefreshBeforeExpiry); err != nil {
		return d, fmt.Errorf("invalid refreshBeforeExpiry: %w", err)
	}
	if d.refreshJitter, err = time.ParseDuration(cfg.RefreshJitter); err != nil {
		return d, fmt.Errorf("invalid refreshJitter: %w", err)
	}
	if d.rulesRefresh, err = time.ParseDuration(cfg.RulesRefresh); err != nil {
		return d, fmt.Errorf("invalid rulesRefreshInterval: %w", err)
	}
	if d.publisherLogsInterval, err = time.ParseDuration(cfg.PublisherLogsInterval); err != nil {
		return d, fmt.Errorf("invalid publisherLogsInterval: %w", err)
	}
	if d.publisherAPIKeyMetadataSyncInterval, err = time.ParseDuration(cfg.PublisherAPIKeyMetadataSyncInterval); err != nil {
		return d, fmt.Errorf("invalid publisherAPIKeyMetadataSyncInterval: %w", err)
	}
	return d, nil
}

func validateConfigTiming(d configDurations) error {
	if d.publisherLogsInterval <= 0 {
		return fmt.Errorf("publisherLogsInterval must be greater than 0")
	}
	if d.publisherAPIKeyMetadataSyncInterval <= 0 {
		return fmt.Errorf("publisherAPIKeyMetadataSyncInterval must be greater than 0")
	}
	if d.refreshBeforeExpiry >= d.cacheTTL {
		return fmt.Errorf("refreshBeforeExpiry must be lower than cacheTTL")
	}
	return nil
}

func validateAbsoluteHTTPSURL(rawURL, fieldName string, allowInsecure bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", fieldName)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if !allowInsecure {
			return fmt.Errorf("%s must use https unless allowInsecureBotRulesURL=true (dev only)", fieldName)
		}
		return nil
	default:
		return fmt.Errorf("%s must use http or https", fieldName)
	}
}

func validatePublisherLogsConfig(cfg *Config) error {
	if err := validateAbsoluteHTTPSURL(cfg.PublisherLogsURL, "publisherLogsURL", cfg.AllowInsecureBotRulesURL); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.PublisherLogsURL) == "" {
		return nil
	}
	bootstrap := strings.TrimSpace(cfg.PublisherAPIKey)
	encrypt := resolvePublisherAPIKeyEncryptAtRest(cfg)
	var encKey []byte
	if encrypt {
		var err error
		encKey, err = loadPublisherEncryptionKey(cfg.PublisherAPIKeyEncryptionKeyFile)
		if err != nil {
			return fmt.Errorf("publisherAPIKeyEncryptAtRest: %w", err)
		}
	}
	if bootstrap == "" && !publisherKeyStateHasSecret(cfg.PublisherAPIKeyStateFile, encrypt, encKey) {
		return fmt.Errorf("publisherAPIKey or an existing publisherAPIKeyStateFile with a secret is required when publisherLogsURL is set")
	}
	if _, err := resolvePublisherAPIBaseURL(cfg.PublisherLogsURL, cfg.PublisherAPIBaseURL); err != nil {
		return fmt.Errorf("publisher API base URL: %w", err)
	}
	return nil
}

func parseAndNormalizeConfig(input *Config) (*parsedConfig, error) {
	cfg := mergeConfigInput(input)
	applyConfigDefaults(cfg)
	normalizeBotRulesURL(cfg)

	if err := validateBotRulesFilePaths(cfg); err != nil {
		return nil, err
	}

	durations, err := parseConfigDurations(cfg)
	if err != nil {
		return nil, err
	}
	if err := validateConfigTiming(durations); err != nil {
		return nil, err
	}
	if err := validateAbsoluteHTTPSURL(cfg.BotRulesURL, "botRulesURL", cfg.AllowInsecureBotRulesURL); err != nil {
		return nil, err
	}
	if err := validatePublisherLogsConfig(cfg); err != nil {
		return nil, err
	}

	cfg.Policy.Normalize()

	nets, err := parseTrustedProxyNetworks(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	encrypt := resolvePublisherAPIKeyEncryptAtRest(cfg)

	return &parsedConfig{
		Config:                              *cfg,
		trustedProxyNets:                    nets,
		cacheTTL:                            durations.cacheTTL,
		refreshBeforeExpiry:                 durations.refreshBeforeExpiry,
		refreshJitter:                       durations.refreshJitter,
		rulesRefresh:                        durations.rulesRefresh,
		publisherLogsInterval:               durations.publisherLogsInterval,
		publisherAPIKeyRotationEnabled:      resolvePublisherAPIKeyRotationEnabled(cfg),
		publisherAPIKeyRotationBufferDays:   cfg.PublisherAPIKeyRotationBufferDays,
		publisherAPIKeyMetadataSyncInterval: durations.publisherAPIKeyMetadataSyncInterval,
		publisherAPIKeyEncryptAtRest:        encrypt,
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
