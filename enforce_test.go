package traefik_bot_wall

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteDeniedResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	message := buildDenyMessage(defaultDenyInfoURL)
	writeDeniedResponse(rec, message)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
		t.Fatalf("unexpected robots header: %s", got)
	}
	if rec.Body.String() != message {
		t.Fatalf("unexpected deny body")
	}
}
