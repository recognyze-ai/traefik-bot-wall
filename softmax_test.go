package traefik_bot_wall

import "testing"

func TestSoftmaxAntiSpoofUAWithoutIP(t *testing.T) {
	c := &Classifier{
		invertedMappings: map[string]string{
			"OpenAI": "ai_access_agents",
		},
		ipBots: map[string]ipVerificationNormalized{
			"openai": {
				RuleCategory:      "OpenAI",
				UserAgentPatterns: []string{"GPTBot"},
				IPRanges:          []string{"10.0.0.0/8"},
			},
		},
	}
	sc := SoftmaxConfig{Enabled: true, Alpha: 4, Beta: 4}
	sm := c.classifySoftmax("GPTBot/1.0", "192.0.2.1", c.ipBots, sc.Alpha, sc.Beta)
	if sm.matched || sm.reason != softmaxReasonWinnerRequiresIP {
		t.Fatalf("expected winner_requires_verified_ip, got matched=%v reason=%q", sm.matched, sm.reason)
	}
}

func TestSoftmaxMatchWhenIPMatches(t *testing.T) {
	c := &Classifier{
		invertedMappings: map[string]string{
			"OpenAI": "ai_access_agents",
		},
		ipBots: map[string]ipVerificationNormalized{
			"openai": {
				RuleCategory:      "OpenAI",
				UserAgentPatterns: []string{"GPTBot"},
				IPRanges:          []string{"10.0.0.0/8"},
			},
		},
	}
	sc := SoftmaxConfig{Enabled: true, Alpha: 4, Beta: 4}
	sm := c.classifySoftmax("GPTBot/1.0", "10.1.2.3", c.ipBots, sc.Alpha, sc.Beta)
	if !sm.matched || sm.reason != softmaxReasonMatched {
		t.Fatalf("expected matched, got matched=%v reason=%q", sm.matched, sm.reason)
	}
}
