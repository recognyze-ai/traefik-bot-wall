package botwall

import (
	"context"
	"log"
	"net"
	"net/http"
)

type Botwall struct {
	name             string
	next             http.Handler
	resolver         *ProtectedResolver
	classifier       *Classifier
	logger           *EventLogger
	policy           PolicyConfig
	softmax          SoftmaxConfig
	trustedProxyNets []*net.IPNet
	denyMessage      string
}

// New wires the middleware runtime components described in ARCHITECTURE.md:
// protected resolver, bot classifier, policy evaluator input, and event logger.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	parsed, err := parseAndNormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	resolver := NewProtectedResolver(parsed)
	classifier, err := NewClassifier(parsed)
	if err != nil {
		return nil, err
	}

	logger := NewEventLogger(parsed)
	logger.StartShippingLoop()

	return &Botwall{
		name:             name,
		next:             next,
		resolver:         resolver,
		classifier:       classifier,
		logger:           logger,
		policy:           parsed.Policy,
		softmax:          softmaxConfigFrom(parsed),
		trustedProxyNets: parsed.trustedProxyNets,
		denyMessage:      buildDenyMessage(fallbackString(parsed.DenyInfoURL, defaultDenyInfoURL)),
	}, nil
}

// ServeHTTP executes the request decision workflow:
// 1) resolve protected path, 2) classify UA, 3) evaluate policy,
// 4) enforce deny or forward allow, 5) emit structured decision event.
func (m *Botwall) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Fast-path pass-through for non-protected paths.
	protected, _, _ := m.resolver.IsProtected(req)
	if !protected {
		m.next.ServeHTTP(rw, req)
		return
	}

	// Protected path: classify traffic and evaluate botwall policy (optionally softmax IP+UA, WordPress parity).
	clientIP, _, _ := extractClientIP(req, m.trustedProxyNets)
	classification, gate := m.classifier.ClassifyForBotWall(req.UserAgent(), clientIP, m.softmax)

	if gate != nil && gate.DenyBeforePolicy {
		writeDeniedResponse(rw, m.denyMessage)
		denyBytes := len(m.denyMessage)
		m.logger.Log(BuildAccessLogEvent(req, clientIP, http.StatusForbidden, denyBytes))
		return
	}

	decision := EvaluateSelectedBotAccess(classification, m.policy)

	if !decision.Allow {
		// Deny path: emit exact 403 contract and log blocked decision.
		writeDeniedResponse(rw, m.denyMessage)
		denyBytes := len(m.denyMessage)
		m.logger.Log(BuildAccessLogEvent(req, clientIP, http.StatusForbidden, denyBytes))
		return
	}

	// Allow path: forward upstream and log resulting upstream status code and response size.
	rec := &responseRecorder{ResponseWriter: rw, statusCode: http.StatusOK}
	m.next.ServeHTTP(rec, req)

	m.logger.Log(BuildAccessLogEvent(req, clientIP, rec.statusCode, rec.bytes))
}

// responseRecorder captures the final upstream status and body size for allow-path logging.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

func init() {
	log.SetFlags(log.LstdFlags | log.LUTC)
}
