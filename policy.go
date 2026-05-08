package botwall

import (
	"strings"
)

// PolicyConfig defines the in-memory policy model used by the middleware's
// policy evaluator stage.
//
// Evaluation order follows the architecture contract:
// 1) Resolve category decision using longest-prefix matching over Rules.
// 2) Apply optional per-bot override from BotOverrides.
// 3) Fall back to GlobalPolicy when no category rule matches.
type PolicyConfig struct {
	GlobalPolicy string            `json:"globalPolicy,omitempty" yaml:"globalPolicy,omitempty"`
	Rules        map[string]string `json:"rules,omitempty" yaml:"rules,omitempty"`
	BotOverrides map[string]string `json:"botOverrides,omitempty" yaml:"botOverrides,omitempty"`
}

// PolicyDecision is the final policy evaluator output consumed by the
// middleware enforcer/logger path.
//
// Reason indicates why the final decision was reached:
// - "not-a-bot"
// - "category-policy"
// - "bot-override-deny"
// - "bot-override-allow"
type PolicyDecision struct {
	Allow            bool
	Reason           string
	CategoryDecision string
	CategoryPath     string
}

// Normalize canonicalizes policy inputs so runtime evaluation stays fast and
// deterministic:
// - GlobalPolicy defaults to "deny" when missing/invalid.
// - Category rule keys are normalized to canonical slash paths.
// - Bot override keys are normalized to slug format.
// - Rule/override values are limited to "allow" or "deny".
func (p *PolicyConfig) Normalize() {
	p.GlobalPolicy = normalizePolicyValue(p.GlobalPolicy, "deny")

	if p.Rules == nil {
		p.Rules = map[string]string{}
	}
	if p.BotOverrides == nil {
		p.BotOverrides = map[string]string{}
	}

	rules := map[string]string{}
	for k, v := range p.Rules {
		key := canonicalCategoryPath(k)
		if key == "" {
			continue
		}
		rules[key] = normalizePolicyValue(v, "")
	}
	p.Rules = rules

	overrides := map[string]string{}
	for k, v := range p.BotOverrides {
		key := slugify(k)
		if key == "" {
			continue
		}
		overrides[key] = normalizePolicyValue(v, "")
	}
	p.BotOverrides = overrides
}

// EvaluateSelectedBotAccess evaluates the final allow/deny decision for a
// classified request.
//
// Behavior is aligned with the architecture workflow:
// - Non-bots are always allowed by policy.
// - Matched bots use longest-prefix category decision first.
// - Per-bot overrides may tighten (allow->deny) or relax (deny->allow) access.
func EvaluateSelectedBotAccess(class Classification, config PolicyConfig) PolicyDecision {
	if !class.Matched {
		return PolicyDecision{
			Allow:            true,
			Reason:           "not-a-bot",
			CategoryDecision: "allow",
			CategoryPath:     "",
		}
	}

	categoryPath := canonicalCategoryPath(class.PolicyCategoryPath())
	categoryDecision := evaluateCategoryPolicy(categoryPath, config)
	finalDecision := categoryDecision
	reason := "category-policy"

	if override, ok := config.BotOverrides[class.BotSlug]; ok {
		override = normalizePolicyValue(override, "")
		switch {
		case categoryDecision == "allow" && override == "deny":
			finalDecision = "deny"
			reason = "bot-override-deny"
		case categoryDecision == "deny" && override == "allow":
			finalDecision = "allow"
			reason = "bot-override-allow"
		}
	}

	return PolicyDecision{
		Allow:            finalDecision != "deny",
		Reason:           reason,
		CategoryDecision: categoryDecision,
		CategoryPath:     categoryPath,
	}
}

// evaluateCategoryPolicy returns the category-level decision for a canonical
// category path using longest-prefix matching up the hierarchy.
func evaluateCategoryPolicy(path string, cfg PolicyConfig) string {
	if path == "" {
		return cfg.GlobalPolicy
	}

	candidate := path
	for candidate != "" {
		if decision, ok := cfg.Rules[candidate]; ok && (decision == "allow" || decision == "deny") {
			return decision
		}
		candidate = parentCategoryPath(candidate)
	}

	return cfg.GlobalPolicy
}

// parentCategoryPath returns the immediate parent category in slash notation.
// Examples:
// - "a/b/c" -> "a/b"
// - "a" -> ""
func parentCategoryPath(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return ""
	}
	return path[:idx]
}

// canonicalCategoryPath normalizes category identifiers into the canonical
// slash-based form used by policy lookup.
//
// Normalizations:
// - trim and lowercase
// - spaces/hyphens -> underscores
// - dots -> slashes
// - remove leading/trailing slash and collapse duplicate separators
func canonicalCategoryPath(path string) string {
	path = strings.TrimSpace(strings.ToLower(path))
	path = strings.ReplaceAll(path, " ", "_")
	path = strings.ReplaceAll(path, "-", "_")
	path = strings.ReplaceAll(path, ".", "/")
	path = strings.Trim(path, "/")
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

// normalizePolicyValue accepts only "allow" or "deny", otherwise returns
// fallback.
func normalizePolicyValue(value string, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "allow", "deny":
		return value
	default:
		return fallback
	}
}
