package traefik_bot_wall

import (
	"errors"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Classification struct {
	Matched         bool
	RuleCategory    string
	TrafficCategory string
	BotSlug         string
}

// PolicyCategoryPath maps classifier output into the canonical category path used
// by policy evaluation. Unclassified non-bot traffic returns empty.
func (c Classification) PolicyCategoryPath() string {
	if c.TrafficCategory != "" {
		return c.TrafficCategory
	}
	if c.Matched {
		return "traditional/bots"
	}
	return ""
}

type botDef struct {
	UAPatterns           []uaPatternEntry          `json:"ua_patterns"`
	CategoryMappings     map[string][]string       `json:"category_mappings"`
	CategoryPatterns     map[string][]string       `json:"category_patterns,omitempty"`
	IPVerificationDoc    *ipVerificationPortalDoc  `json:"ipVerification,omitempty"`
	LegacyIPVerification map[string]legacyVerifier `json:"ip_verification,omitempty"`
}

type uaPatternEntry struct {
	Category string   `json:"category"`
	Patterns []string `json:"patterns"`
}

type uaMatcherEntry struct {
	ruleCategory    string
	trafficCategory string
	pattern         string
}

type categoryMatcherEntry struct {
	trafficCategory string
	pattern         string
}

// Classifier resolves user-agent traffic category from active bot definitions.
//
// It keeps classify hot-path reads lock-light by taking a read snapshot of defs
// and only using write locks when rotating definitions/refresh state.
type Classifier struct {
	cfg *parsedConfig

	mu               sync.RWMutex
	defs             botDef
	ipBots           map[string]ipVerificationNormalized
	invertedMappings map[string]string
	uaMatchers       []uaMatcherEntry
	categoryMatchers []categoryMatcherEntry
	ruleSource       string
	refreshing       bool
	nextSync         time.Time
	httpClient       *http.Client
	remoteEnabled    bool
}

// NewClassifier builds the classifier and initializes rule sources according to
// startup precedence, then enables remote refresh when configured.
func NewClassifier(cfg *parsedConfig) (*Classifier, error) {
	c := &Classifier{
		cfg:           cfg,
		nextSync:      time.Now().Add(cfg.rulesRefresh),
		ruleSource:    "local_file",
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		remoteEnabled: strings.TrimSpace(cfg.BotRulesURL) != "",
	}

	if err := c.bootstrapRules(); err != nil {
		return nil, err
	}
	return c, nil
}

// bootstrapRules applies startup rule-source precedence:
//  1. default_file as hard baseline
//  2. local_file override when configured and readable
//  3. remote_cached_fallback when remote cache is available and not older than local
//
// If remote rules are enabled, it schedules background refresh checks.
func (c *Classifier) bootstrapRules() error {
	// Default local file is the hard fallback baseline.
	defaultDefs, err := readDefaultBotDefFromFile()
	if err != nil {
		return err
	}
	c.setDefs(defaultDefs, "default_file")

	localRulesPath := strings.TrimSpace(c.cfg.BotRulesFile)
	var localModTime time.Time
	if strings.TrimSpace(c.cfg.BotRulesFile) != "" {
		localDefs, err := readBotDefFromFile(c.cfg.BotRulesFile)
		if err == nil {
			c.setDefs(localDefs, "local_file")
		} else {
			log.Printf("[botwall] bot rules file read failed (%s): %v", c.cfg.BotRulesFile, err)
		}
		localModTime = fileModTime(localRulesPath)
	}

	if c.remoteEnabled {
		cachePath := strings.TrimSpace(c.cfg.RulesCacheFile)
		cacheDefs, err := readBotDefFromFile(cachePath)
		if err == nil {
			cacheModTime := fileModTime(cachePath)
			shouldApplyCache := !cacheModTime.IsZero() &&
				(localModTime.IsZero() || !cacheModTime.Before(localModTime))
			if shouldApplyCache && c.cfg.PreferLocalBotRulesFile && !localModTime.IsZero() {
				log.Printf(
					"[botwall] startup rules source kept local file (%s) over cache (%s) because preferLocalBotRulesFile=true",
					c.cfg.BotRulesFile,
					cachePath,
				)
			} else if shouldApplyCache {
				c.setDefs(cacheDefs, "remote_cached_fallback")
				log.Printf(
					"[botwall] startup rules source set to remote cache (%s); local file (%s) was not newer",
					cachePath,
					c.cfg.BotRulesFile,
				)
			}
		}

		go c.refreshRulesIfDue()
	}
	return nil
}

// RuleSource returns the currently active rule source for observability/logging.
func (c *Classifier) RuleSource() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ruleSource
}

// Classify evaluates a user-agent against current rule snapshots and returns a
// normalized classification payload for policy evaluation.
//
// Matching order:
//  1. ua_patterns
//  2. category_patterns fallback
//  3. conservative keyword fallback (bot/crawl/spider)
func (c *Classifier) Classify(userAgent string) Classification {
	if c.remoteEnabled {
		c.refreshRulesIfDue()
	}

	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return Classification{}
	}

	c.mu.RLock()
	uaMatchers := c.uaMatchers
	categoryMatchers := c.categoryMatchers
	c.mu.RUnlock()

	for _, matcher := range uaMatchers {
		if strings.Contains(ua, matcher.pattern) {
			return Classification{
				Matched:         true,
				RuleCategory:    matcher.ruleCategory,
				TrafficCategory: matcher.trafficCategory,
				BotSlug:         slugify(matcher.ruleCategory),
			}
		}
	}

	for _, matcher := range categoryMatchers {
		if strings.Contains(ua, matcher.pattern) {
			return Classification{
				Matched:         true,
				RuleCategory:    "",
				TrafficCategory: matcher.trafficCategory,
				BotSlug:         "",
			}
		}
	}

	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawl") || strings.Contains(ua, "spider") {
		return Classification{
			Matched:         true,
			RuleCategory:    "",
			TrafficCategory: "traditional/bots",
			BotSlug:         "",
		}
	}

	return Classification{}
}

// refreshRulesIfDue starts at most one async remote refresh when nextSync is due.
// Failures preserve the current in-memory definitions and retry at next interval.
func (c *Classifier) refreshRulesIfDue() {
	if !c.remoteEnabled {
		return
	}

	now := time.Now()
	c.mu.RLock()
	refreshing := c.refreshing
	nextSync := c.nextSync
	c.mu.RUnlock()
	if refreshing || now.Before(nextSync) {
		return
	}

	c.mu.Lock()
	// Re-check under write lock to avoid duplicate refresh goroutines.
	if c.refreshing || time.Now().Before(c.nextSync) {
		c.mu.Unlock()
		return
	}
	c.refreshing = true
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.refreshing = false
			c.nextSync = time.Now().Add(c.cfg.rulesRefresh)
			c.mu.Unlock()
		}()

		remoteDefs, err := readBotDefFromURL(c.httpClient, c.cfg.BotRulesURL)
		if err != nil {
			log.Printf("[botwall] bot rules refresh failed: %v", err)
			return
		}

		c.mu.Lock()
		if strings.EqualFold(c.cfg.RulesMergeStrategy, "merge") {
			c.setDefs(mergeBotDefs(c.defs, remoteDefs), "remote_fresh")
		} else {
			c.setDefs(remoteDefs, "remote_fresh")
		}
		c.mu.Unlock()

		if err := writeJSON(c.cfg.RulesCacheFile, remoteDefs); err != nil {
			log.Printf("[botwall] bot rules cache write failed: %v", err)
		}
		if localPath := strings.TrimSpace(c.cfg.BotRulesFile); localPath != "" {
			if err := writeJSON(localPath, remoteDefs); err != nil {
				log.Printf("[botwall] bot rules file update failed (%s): %v", localPath, err)
			}
		}
	}()
}

// setDefs swaps active definitions and derived indexes atomically under lock.
func (c *Classifier) setDefs(defs botDef, source string) {
	c.defs = defs
	c.ipBots = buildIPVerificationIndex(defs)
	c.invertedMappings = invertMappings(defs.CategoryMappings)
	c.uaMatchers = buildUAMatchers(defs.UAPatterns, c.invertedMappings)
	c.categoryMatchers = buildCategoryMatchers(defs.CategoryPatterns)
	c.ruleSource = source
}

// mergeBotDefs overlays non-empty remote sections on top of the current baseline.
func mergeBotDefs(base, remote botDef) botDef {
	if len(remote.UAPatterns) > 0 {
		base.UAPatterns = remote.UAPatterns
	}
	if len(remote.CategoryMappings) > 0 {
		base.CategoryMappings = remote.CategoryMappings
	}
	if len(remote.CategoryPatterns) > 0 {
		base.CategoryPatterns = remote.CategoryPatterns
	}
	if remote.IPVerificationDoc != nil {
		base.IPVerificationDoc = remote.IPVerificationDoc
	}
	if len(remote.LegacyIPVerification) > 0 {
		base.LegacyIPVerification = remote.LegacyIPVerification
	}
	return base
}

// invertMappings builds a reverse index from rule category to traffic category.
func invertMappings(input map[string][]string) map[string]string {
	out := map[string]string{}
	for traffic, categories := range input {
		for _, category := range categories {
			out[strings.TrimSpace(category)] = traffic
		}
	}
	return out
}

// canonicalTrafficCategory normalizes synonyms into policy canonical categories.
func canonicalTrafficCategory(raw string) string {
	canonical := canonicalCategoryPath(raw)
	switch canonical {
	case "ai_access_agents", "ai/access_patterns":
		return "ai/access_agents"
	case "ai_data_scrapers", "ai/scraper_patterns":
		return "ai/data_scrapers"
	case "traditional_bots", "traditional/bot_patterns":
		return "traditional/bots"
	default:
		return canonical
	}
}

// normalizePattern returns a lower-cased, prefix-normalized matching token.
func normalizePattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimPrefix(pattern, "+")
	return pattern
}

func buildUAMatchers(entries []uaPatternEntry, invertedMappings map[string]string) []uaMatcherEntry {
	out := make([]uaMatcherEntry, 0, len(entries)*2)
	for _, entry := range entries {
		ruleCategory := strings.TrimSpace(entry.Category)
		trafficCategory := canonicalTrafficCategory(invertedMappings[ruleCategory])
		for _, p := range entry.Patterns {
			normalized := normalizePattern(p)
			if normalized == "" {
				continue
			}
			out = append(out, uaMatcherEntry{
				ruleCategory:    ruleCategory,
				trafficCategory: trafficCategory,
				pattern:         normalized,
			})
		}
	}
	return out
}

func buildCategoryMatchers(categoryPatterns map[string][]string) []categoryMatcherEntry {
	out := make([]categoryMatcherEntry, 0, len(categoryPatterns)*2)
	keys := make([]string, 0, len(categoryPatterns))
	for traffic := range categoryPatterns {
		keys = append(keys, traffic)
	}
	sort.Strings(keys)
	for _, traffic := range keys {
		normalizedTraffic := canonicalTrafficCategory(traffic)
		for _, p := range categoryPatterns[traffic] {
			normalized := normalizePattern(p)
			if normalized == "" {
				continue
			}
			out = append(out, categoryMatcherEntry{
				trafficCategory: normalizedTraffic,
				pattern:         normalized,
			})
		}
	}
	return out
}

// readBotDefFromFile loads bot definitions from JSON on disk.
func readBotDefFromFile(path string) (botDef, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return botDef{}, err
	}
	return parseBotDefinitionJSON(body)
}

// fileModTime returns zero time for missing/unreadable files.
func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("[botwall] file stat failed (%s): %v", path, err)
		}
		return time.Time{}
	}
	return info.ModTime()
}
