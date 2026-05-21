package traefik_bot_wall

import (
	"reflect"
	"testing"
)

// IP/CIDR strings are fixtures only: normalizeIPVerificationBots trims and merges
// entries; it does not parse or match networks. Use RFC 5737 TEST-NET (192.0.2.0/24)
// and private space (10.0.0.0/8) so tests stay offline and unrelated to live bot ranges.
func TestNormalizeIPVerificationBots(t *testing.T) {
	p := botDefParsed{
		UAPatterns: []uaPatternEntry{
			{Category: "OpenAI", Patterns: []string{"GPTBot"}},
		},
		IPVerification: &ipVerificationPortalDoc{
			Bots: map[string]portalIPBot{
				"openai": {
					UserAgentPatterns: []string{" GPTBot ", ""},
					IPRanges:          []string{" 10.0.0.0/8 "},
				},
			},
		},
		LegacyIPv: map[string]legacyVerifier{
			"legacy-bot": {
				UAPatterns: []string{" LegacyBot "},
				CIDRs:      []string{"192.0.2.0/24"},
			},
			"openai": {
				UAPatterns: []string{"should-not-override"},
			},
		},
	}

	got := normalizeIPVerificationBots(p)

	wantOpenAI := ipVerificationNormalized{
		RuleCategory:      "OpenAI",
		UserAgentPatterns: []string{"GPTBot"},
		IPRanges:          []string{"10.0.0.0/8"},
	}
	if !reflect.DeepEqual(got["openai"], wantOpenAI) {
		t.Fatalf("openai: got %+v want %+v", got["openai"], wantOpenAI)
	}

	wantLegacy := ipVerificationNormalized{
		RuleCategory:      "legacy-bot",
		UserAgentPatterns: []string{"LegacyBot"},
		IPRanges:          []string{"192.0.2.0/24"},
	}
	if !reflect.DeepEqual(got["legacy-bot"], wantLegacy) {
		t.Fatalf("legacy-bot: got %+v want %+v", got["legacy-bot"], wantLegacy)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 bots, got %d: %+v", len(got), got)
	}
}
