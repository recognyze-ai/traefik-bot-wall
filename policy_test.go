package botwall

import "testing"

func TestEvaluateSelectedBotAccessWithOverride(t *testing.T) {
	cfg := PolicyConfig{
		GlobalPolicy: "deny",
		Rules: map[string]string{
			"ai/access_agents": "deny",
		},
		BotOverrides: map[string]string{
			"openai": "allow",
		},
	}
	cfg.Normalize()

	class := Classification{
		Matched:         true,
		RuleCategory:    "OpenAI",
		TrafficCategory: "ai/access_agents",
		BotSlug:         "openai",
	}
	decision := EvaluateSelectedBotAccess(class, cfg)
	if !decision.Allow {
		t.Fatalf("expected allow due to bot override, got deny")
	}
	if decision.Reason != "bot-override-allow" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}

func TestEvaluateCategoryLongestPrefix(t *testing.T) {
	cfg := PolicyConfig{
		GlobalPolicy: "deny",
		Rules: map[string]string{
			"ai": "allow",
		},
	}
	cfg.Normalize()

	got := evaluateCategoryPolicy("ai/access_agents/openai", cfg)
	if got != "allow" {
		t.Fatalf("expected allow from parent rule, got %s", got)
	}
}
