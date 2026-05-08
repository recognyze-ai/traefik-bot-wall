package botwall

import (
	"strings"
	"testing"
)

func TestExtractRecognyzeURL(t *testing.T) {
	robots := `
# START YOAST BLOCK
User-agent: *
Disallow:
Recognyze: https://bertrandmeyer.com/recognyze.txt
Sitemap: https://bertrandmeyer.com/sitemap_index.xml
`
	url := extractRecognyzeURL(robots, "https://bertrandmeyer.com/robots.txt")
	if url != "https://bertrandmeyer.com/recognyze.txt" {
		t.Fatalf("unexpected url: %s", url)
	}
}

func TestParseRecognyzePaths(t *testing.T) {
	body := strings.Join([]string{
		"# comment",
		"/signed/page-a",
		"signed/page-b",
		"https://example.com/signed/page-c",
		"/signed/section/*",
		"",
	}, "\n")

	paths := parseRecognyzePaths(body)
	if len(paths) != 4 {
		t.Fatalf("expected 4 paths, got %d", len(paths))
	}
	if !matchesProtectedPath("/signed/section/any", paths) {
		t.Fatalf("expected wildcard match")
	}
	if !matchesProtectedPath("/signed/page-c", paths) {
		t.Fatalf("expected absolute url path match")
	}
}
