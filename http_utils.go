package botwall

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (r *ProtectedResolver) fetchWithConditionals(targetURL string, etag string, lastModified string) ([]byte, string, string, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := r.http.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	newEtag := strings.TrimSpace(resp.Header.Get("ETag"))
	newLastMod := strings.TrimSpace(resp.Header.Get("Last-Modified"))

	if resp.StatusCode == http.StatusNotModified {
		return nil, newEtag, newLastMod, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, targetURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", err
	}
	return body, newEtag, newLastMod, nil
}

func readBotDefFromURL(client *http.Client, targetURL string) (botDef, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return botDef{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return botDef{}, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return botDef{}, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, targetURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return botDef{}, err
	}
	return parseBotDefinitionJSON(body)
}

func requestScheme(req *http.Request) string {
	if xf := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); xf != "" {
		return xf
	}
	if req.URL != nil && req.URL.Scheme != "" {
		return req.URL.Scheme
	}
	return "https"
}
