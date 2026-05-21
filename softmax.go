package traefik_bot_wall

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

type softmaxCand struct {
	botSlug      string
	ruleCategory string
	uaMatched    bool
	ipMatched    bool
	z            float64
	exp          float64
	probability  float64
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

func buildSoftmaxCandidates(userAgent, visitorIP string, ipBots map[string]ipVerificationNormalized, alpha, beta float64) (map[string]*softmaxCand, float64, bool) {
	cs := make(map[string]*softmaxCand, len(ipBots))
	var maxZ float64
	hasMax := false
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
		cs[botSlug] = &softmaxCand{
			botSlug:      botSlug,
			ruleCategory: def.RuleCategory,
			uaMatched:    uaMatched,
			ipMatched:    ipMatched,
			z:            z,
		}
		if !hasMax || z > maxZ {
			maxZ = z
			hasMax = true
		}
	}
	return cs, maxZ, hasMax
}

func computeSoftmaxProbabilities(cs map[string]*softmaxCand, maxZ float64) (selectedSlug string, sumExp float64, ok bool) {
	sumExp = 0.0
	for slug, e := range cs {
		ev := math.Exp(e.z - maxZ)
		cs[slug].exp = ev
		sumExp += ev
	}
	if sumExp <= 0 {
		return "", 0, false
	}

	var selectedProb float64 = -1
	for slug, e := range cs {
		p := e.exp / sumExp
		cs[slug].probability = p
		if p > selectedProb {
			selectedProb = p
			selectedSlug = slug
		}
	}
	return selectedSlug, sumExp, selectedSlug != "" && cs[selectedSlug] != nil
}

func softmaxOutcomeFromSelection(sel *softmaxCand, winnerRanges []string) softmaxOutcome {
	out := softmaxOutcome{
		botSlug:      sel.botSlug,
		ruleCategory: sel.ruleCategory,
		uaMatched:    sel.uaMatched,
		ipMatched:    sel.ipMatched,
		probability:  sel.probability,
	}
	if len(winnerRanges) > 0 && !sel.ipMatched {
		out.matched = false
		out.reason = softmaxReasonWinnerRequiresIP
		return out
	}
	out.matched = true
	out.reason = softmaxReasonMatched
	return out
}

func (c *Classifier) classifySoftmax(userAgent, visitorIP string, ipBots map[string]ipVerificationNormalized, alpha, beta float64) softmaxOutcome {
	out := softmaxOutcome{reason: softmaxReasonNoEvidence}

	cs, maxZ, hasMax := buildSoftmaxCandidates(userAgent, visitorIP, ipBots, alpha, beta)
	if len(cs) == 0 {
		out.reason = softmaxReasonNoCandidates
		return out
	}
	if !hasMax || maxZ <= 0 {
		out.reason = softmaxReasonNoEvidence
		return out
	}

	selectedSlug, sumExp, ok := computeSoftmaxProbabilities(cs, maxZ)
	if !ok {
		if sumExp <= 0 {
			out.reason = softmaxReasonSoftmaxError
			return out
		}
		out.reason = softmaxReasonSelectionFailed
		return out
	}

	return softmaxOutcomeFromSelection(cs[selectedSlug], ipBots[selectedSlug].IPRanges)
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

var genericUAIdentitySlugs = map[string]struct{}{
	"human": {}, "unknown": {}, "other": {}, "mozilla": {},
	"chrome": {}, "safari": {}, "firefox": {}, "opera": {},
	"edge": {}, "curl": {}, "wget": {},
}

func isPlausibleIPVerificationIdentityUA(ua string) bool {
	ul := len(ua)
	if ul < 3 || ul > 96 {
		return false
	}
	return !strings.ContainsAny(ua, " ;(),/<>")
}

func isGenericUAIdentitySlug(uaSlug string) bool {
	_, ok := genericUAIdentitySlugs[uaSlug]
	return ok
}

func userAgentMatchesIPVerificationBotIdentity(userAgent string, botSlug string, ruleCategory string) bool {
	if strings.TrimSpace(userAgent) == "" || botSlug == "" {
		return false
	}
	ua := strings.TrimSpace(userAgent)
	if !isPlausibleIPVerificationIdentityUA(ua) {
		return false
	}
	uaSlug := slugify(ua)
	if len(uaSlug) < 3 || isGenericUAIdentitySlug(uaSlug) {
		return false
	}
	if uaSlug == botSlug {
		return true
	}
	return ruleCategory != "" && slugify(ruleCategory) == uaSlug
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
