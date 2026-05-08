package botwall

import (
	"math"
	"net"
	"strings"
)

// softmaxReason values align with recognyze-client/includes/access-logs.php (wprc_classify_request_bot_softmax).
const (
	softmaxReasonNoCandidates     = "no_candidates"
	softmaxReasonNoEvidence       = "no_evidence"
	softmaxReasonSoftmaxError     = "softmax_error"
	softmaxReasonWinnerRequiresIP = "winner_requires_verified_ip"
	softmaxReasonMatched          = "matched"
	softmaxReasonSelectionFailed  = "selection_failed"

	decisionMethodSoftmaxArgmax  = "softmax_argmax"
	decisionGateUAOnlyRejected   = "legacy_ua_blocked_by_ip_ranges"
	gateWinnerRequiresVerifiedIP = "winner_requires_verified_ip"
	gateUAOnlyRejected           = "ua_only_rejected"
)

// SoftmaxConfig toggles softmax IP+UA bot attribution vs UA-only classifier (WordPress parity).
type SoftmaxConfig struct {
	Enabled bool
	Alpha   float64
	Beta    float64
}

// SoftmaxDecisionLog carries optional attribution metadata when softmax mode is consulted.
type SoftmaxDecisionLog struct {
	Reason         string
	DecisionMethod string
	BlockReason    string
	BotSlug        string
	RuleCategory   string
	UAMatched      bool
	IPMatched      bool
	Probability    float64
}

// ClassificationGate is returned alongside classification when softmax can force deny before category policy.
type ClassificationGate struct {
	DenyBeforePolicy bool
	Log              SoftmaxDecisionLog
}

// ClassifyForBotWall mirrors WordPress `wprc_is_bot_allowed_for_signed_content` routing:
// softmax path first when enabled and ip bots exist; then legacy ua_patterns with UA-only IP rejection.
func (c *Classifier) ClassifyForBotWall(userAgent, visitorIP string, sc SoftmaxConfig) (Classification, *ClassificationGate) {
	if !sc.Enabled {
		cl := c.Classify(userAgent)
		return cl, nil
	}

	c.mu.RLock()
	ipBots := c.ipBots
	c.mu.RUnlock()

	if len(ipBots) == 0 {
		cl := c.Classify(userAgent)
		return cl, nil
	}

	sm := c.classifySoftmax(userAgent, visitorIP, ipBots, sc.Alpha, sc.Beta)

	if sm.matched {
		return softmaxToClassification(sm, c), nil
	}

	if sm.reason == softmaxReasonWinnerRequiresIP {
		return Classification{}, &ClassificationGate{
			DenyBeforePolicy: true,
			Log: SoftmaxDecisionLog{
				Reason:         softmaxReasonWinnerRequiresIP,
				DecisionMethod: decisionMethodSoftmaxArgmax,
				BlockReason:    gateWinnerRequiresVerifiedIP,
				BotSlug:        sm.botSlug,
				RuleCategory:   sm.ruleCategory,
				UAMatched:      sm.uaMatched,
				IPMatched:      false,
				Probability:    sm.probability,
			},
		}
	}

	cl := c.Classify(userAgent)
	if cl.Matched && ipVerificationDeniesUAOnlyClaim(slugify(cl.RuleCategory), visitorIP, ipBots) {
		return cl, &ClassificationGate{
			DenyBeforePolicy: true,
			Log: SoftmaxDecisionLog{
				Reason:         sm.reason,
				DecisionMethod: decisionGateUAOnlyRejected,
				BlockReason:    gateUAOnlyRejected,
				BotSlug:        cl.BotSlug,
				RuleCategory:   cl.RuleCategory,
				UAMatched:      true,
				IPMatched:      false,
				Probability:    0,
			},
		}
	}

	return cl, nil
}

type softmaxOutcome struct {
	matched      bool
	reason       string
	botSlug      string
	ruleCategory string
	probability  float64
	uaMatched    bool
	ipMatched    bool
}

func softmaxToClassification(sm softmaxOutcome, c *Classifier) Classification {
	c.mu.RLock()
	inverted := c.invertedMappings
	c.mu.RUnlock()
	tc := canonicalTrafficCategory(inverted[sm.ruleCategory])
	botSlug := slugify(sm.ruleCategory)
	return Classification{
		Matched:         true,
		RuleCategory:    sm.ruleCategory,
		TrafficCategory: tc,
		BotSlug:         botSlug,
	}
}

func (c *Classifier) classifySoftmax(userAgent, visitorIP string, ipBots map[string]ipVerificationNormalized, alpha, beta float64) softmaxOutcome {
	out := softmaxOutcome{reason: softmaxReasonNoEvidence}

	type cand struct {
		botSlug      string
		ruleCategory string
		uaMatched    bool
		ipMatched    bool
		z            float64
		exp          float64
		probability  float64
	}

	cs := map[string]*cand{}
	var maxZPtr *float64
	for botSlug, def := range ipBots {
		uaMatched := softmaxUAMatches(userAgent, botSlug, def)
		ipMatched := visitorIP != "" && ipMatchesRanges(visitorIP, def.IPRanges)
		z := 0.0
		if uaMatched {
			z += alpha
		}
		if ipMatched {
			z += beta
		}
		cs[botSlug] = &cand{
			botSlug:      botSlug,
			ruleCategory: def.RuleCategory,
			uaMatched:    uaMatched,
			ipMatched:    ipMatched,
			z:            z,
		}
		if maxZPtr == nil || z > *maxZPtr {
			zCopy := z
			maxZPtr = &zCopy
		}
	}

	if len(cs) == 0 {
		out.reason = softmaxReasonNoCandidates
		return out
	}
	if maxZPtr == nil || *maxZPtr <= 0 {
		out.reason = softmaxReasonNoEvidence
		return out
	}

	mz := *maxZPtr
	sumExp := 0.0
	for slug, e := range cs {
		ev := math.Exp(e.z - mz)
		cs[slug].exp = ev
		sumExp += ev
	}

	if sumExp <= 0 {
		out.reason = softmaxReasonSoftmaxError
		return out
	}

	var selectedSlug string
	var selectedProb float64 = -1
	for slug, e := range cs {
		p := e.exp / sumExp
		cs[slug].probability = p
		if p > selectedProb {
			selectedProb = p
			selectedSlug = slug
		}
	}

	if selectedSlug == "" || cs[selectedSlug] == nil {
		out.reason = softmaxReasonSelectionFailed
		return out
	}

	sel := cs[selectedSlug]
	out.botSlug = sel.botSlug
	out.ruleCategory = sel.ruleCategory
	out.uaMatched = sel.uaMatched
	out.ipMatched = sel.ipMatched
	out.probability = sel.probability

	winnerRanges := ipBots[selectedSlug].IPRanges

	if len(winnerRanges) > 0 && !sel.ipMatched {
		out.matched = false
		out.reason = softmaxReasonWinnerRequiresIP
		return out
	}

	out.matched = true
	out.reason = softmaxReasonMatched
	return out
}

func softmaxUAMatches(userAgent string, botSlug string, def ipVerificationNormalized) bool {
	uaMatched := false
	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range def.UserAgentPatterns {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		if strings.Contains(userAgentLower, strings.ToLower(p)) {
			uaMatched = true
			break
		}
	}
	if uaMatched {
		return true
	}
	return userAgentMatchesIPVerificationBotIdentity(userAgent, botSlug, def.RuleCategory)
}

func userAgentMatchesIPVerificationBotIdentity(userAgent string, botSlug string, ruleCategory string) bool {
	if strings.TrimSpace(userAgent) == "" || botSlug == "" {
		return false
	}
	ua := strings.TrimSpace(userAgent)
	ul := len(ua)
	if ul < 3 || ul > 96 {
		return false
	}
	for _, r := range ua {
		if r == ' ' || r == ';' || r == '(' || r == ')' || r == ',' || r == '/' || r == '<' || r == '>' {
			return false
		}
	}
	uaSlug := slugify(ua)
	if len(uaSlug) < 3 {
		return false
	}
	generic := map[string]struct{}{
		"human": {}, "unknown": {}, "other": {}, "mozilla": {},
		"chrome": {}, "safari": {}, "firefox": {}, "opera": {},
		"edge": {}, "curl": {}, "wget": {},
	}
	if _, ok := generic[uaSlug]; ok {
		return false
	}
	if uaSlug == botSlug {
		return true
	}
	if ruleCategory != "" && slugify(ruleCategory) == uaSlug {
		return true
	}
	return false
}

func ipMatchesRanges(ipStr string, ranges []string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}
	host, _, splitErr := net.SplitHostPort(ipStr)
	if splitErr == nil && host != "" {
		ipStr = host
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range ranges {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			o := net.ParseIP(cidr)
			if o != nil && ip.Equal(o) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ipVerificationDeniesUAOnlyClaim(botSlug string, visitorIP string, ipBots map[string]ipVerificationNormalized) bool {
	if botSlug == "" || len(ipBots) == 0 {
		return false
	}

	def, ok := ipBots[botSlug]
	if !ok || len(def.IPRanges) == 0 {
		return false
	}

	if strings.TrimSpace(visitorIP) == "" {
		return true
	}

	return !ipMatchesRanges(visitorIP, def.IPRanges)
}

func softmaxConfigFrom(p *parsedConfig) SoftmaxConfig {
	return SoftmaxConfig{
		Enabled: p.EnableIPSoftmax,
		Alpha:   p.SoftmaxAlpha,
		Beta:    p.SoftmaxBeta,
	}
}
