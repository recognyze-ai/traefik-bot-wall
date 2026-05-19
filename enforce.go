package traefik_bot_wall

import "net/http"

const defaultDenyInfoURL = "https://www.recognyze.ai/aggregators"

func buildDenyMessage(infoURL string) string {
	return "Automated tools are only permitted to access this page if registered with Recognyze AI. To register, see " + infoURL
}

func writeDeniedResponse(rw http.ResponseWriter, message string) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("X-Robots-Tag", "noindex, nofollow")
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	rw.Header().Set("Pragma", "no-cache")
	rw.Header().Set("Expires", "0")
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte(message))
}
