package traefik_bot_wall

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ipVerificationNormalized mirrors recognyze-client's wprc_normalize_ip_verification_bots output per bot slug.
type ipVerificationNormalized struct {
	RuleCategory      string
	UserAgentPatterns []string
	IPRanges          []string
}

type botDefParsed struct {
	UAPatterns       []uaPatternEntry          `json:"ua_patterns"`
	CategoryMappings map[string][]string       `json:"category_mappings"`
	CategoryPatterns map[string][]string       `json:"category_patterns,omitempty"`
	IPVerification   *ipVerificationPortalDoc  `json:"ipVerification,omitempty"`
	LegacyIPv        map[string]legacyVerifier `json:"ip_verification,omitempty"`
}

type ipVerificationPortalDoc struct {
	Bots map[string]portalIPBot `json:"bots"`
}

type portalIPBot struct {
	UserAgentPatterns []string `json:"userAgentPatterns"`
	IPRanges          []string `json:"ipRanges"`
}

type legacyVerifier struct {
	UAPatterns []string `json:"ua_patterns"`
	CIDRs      []string `json:"cidr_ranges"`
}

// parseBotDefinitionJSON unmarshals Bot Rules JSON, including the portal/API envelope `{ "bot_rules": { ... } }`.
func parseBotDefinitionJSON(body []byte) (botDef, error) {
	var wrap struct {
		BotRules *botDefParsed `json:"bot_rules"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && wrap.BotRules != nil && botDefLooksPresent(wrap.BotRules) {
		return finalizeParsedBotDef(*wrap.BotRules)
	}

	var flat botDefParsed
	if err := json.Unmarshal(body, &flat); err != nil {
		return botDef{}, fmt.Errorf("parse bot definitions: %w", err)
	}
	if !botDefLooksPresent(&flat) {
		return botDef{}, fmt.Errorf("parse bot definitions: missing ua_patterns/category_mappings")
	}
	return finalizeParsedBotDef(flat)
}

func botDefLooksPresent(p *botDefParsed) bool {
	if p == nil {
		return false
	}
	return len(p.UAPatterns) > 0 || len(p.CategoryMappings) > 0
}

func finalizeParsedBotDef(p botDefParsed) (botDef, error) {
	out := botDef{
		UAPatterns:           p.UAPatterns,
		CategoryMappings:     p.CategoryMappings,
		CategoryPatterns:     p.CategoryPatterns,
		IPVerificationDoc:    p.IPVerification,
		LegacyIPVerification: p.LegacyIPv,
	}
	return out, nil
}

// buildIPVerificationIndex derives the runtime IP verification lookup from embedded JSON fields (recognyze portal + legacy).
func buildIPVerificationIndex(d botDef) map[string]ipVerificationNormalized {
	p := botDefParsed{
		UAPatterns:     d.UAPatterns,
		IPVerification: d.IPVerificationDoc,
		LegacyIPv:      d.LegacyIPVerification,
	}
	return normalizeIPVerificationBots(p)
}

// ruleCategoryBySlug maps slugified rule category keys (e.g. openai) to display rule names (e.g. OpenAI), from ua_patterns.
func ruleCategoryBySlug(uaPatterns []uaPatternEntry) map[string]string {
	out := make(map[string]string)
	for _, e := range uaPatterns {
		rule := strings.TrimSpace(e.Category)
		if rule == "" {
			continue
		}
		s := slugify(rule)
		if s != "" {
			out[s] = rule
		}
	}
	return out
}

func trimNonEmptyStrings(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func normalizeIPVerificationBots(p botDefParsed) map[string]ipVerificationNormalized {
	out := make(map[string]ipVerificationNormalized)
	bySlug := ruleCategoryBySlug(p.UAPatterns)
	normalizePortalIPBots(p, bySlug, out)
	normalizeLegacyIPBots(p, bySlug, out)
	return out
}

func normalizePortalIPBots(p botDefParsed, bySlug map[string]string, out map[string]ipVerificationNormalized) {
	if p.IPVerification == nil {
		return
	}
	for botKey, def := range p.IPVerification.Bots {
		botSlug := slugify(botKey)
		if botSlug == "" {
			continue
		}
		ruleCat := bySlug[botSlug]
		if ruleCat == "" {
			ruleCat = titleFirstSegment(botKey)
		}
		out[botSlug] = ipVerificationNormalized{
			RuleCategory:      ruleCat,
			UserAgentPatterns: trimNonEmptyStrings(def.UserAgentPatterns),
			IPRanges:          trimNonEmptyStrings(def.IPRanges),
		}
	}
}

func normalizeLegacyIPBots(p botDefParsed, bySlug map[string]string, out map[string]ipVerificationNormalized) {
	for slug, leg := range p.LegacyIPv {
		slug = slugify(slug)
		if slug == "" {
			continue
		}
		if _, ok := out[slug]; ok {
			continue
		}
		ruleCat := bySlug[slug]
		if ruleCat == "" {
			ruleCat = slug
		}
		out[slug] = ipVerificationNormalized{
			RuleCategory:      ruleCat,
			UserAgentPatterns: trimNonEmptyStrings(leg.UAPatterns),
			IPRanges:          trimNonEmptyStrings(leg.CIDRs),
		}
	}
}

func titleFirstSegment(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	// Mirrors PHP-ish ucfirst(slug): use first segment after replacing separators.
	key = strings.ReplaceAll(key, "-", "_")
	parts := strings.SplitN(key, "_", 2)
	r := parts[0]
	if r == "" {
		return ""
	}
	// ASCII title: first letter upper, rest lower.
	fl := strings.ToUpper(r[:1]) + strings.ToLower(r[1:])
	return fl
}
