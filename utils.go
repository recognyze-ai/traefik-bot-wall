package botwall

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = nonSlugChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	return value
}

func parseClientIPCandidate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Try host:port first when port is present.
	if strings.Count(value, ":") == 1 || strings.Contains(value, "]:") {
		if host, port, err := net.SplitHostPort(value); err == nil && host != "" && port != "" {
			if _, err := strconv.Atoi(port); err == nil {
				value = host
			}
		}
	}
	value = strings.Trim(value, "[]")
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func extractClientIP(req *http.Request, trusted []*net.IPNet) (ip string, source string, trustedPath bool) {
	peer := parsePeerIP(req.RemoteAddr)

	trustHeaders := len(trusted) == 0
	if !trustHeaders && peer != nil {
		trustHeaders = ipInAnyNet(peer, trusted)
	}

	if trustHeaders {
		ip, src, hdrOK := forwardedClientFromHeaders(req)
		if hdrOK {
			pathTrusted := trustedPathFromHeaders(trusted)
			return ip, src, pathTrusted
		}
	}

	if parsed := parseClientIPCandidate(strings.TrimSpace(req.RemoteAddr)); parsed != "" {
		return parsed, "remote_addr", true
	}
	return "", "", false
}

// trustedPathFromHeaders mirrors legacy semantics: forwarded headers alone are not "cryptographically tied"
// to RemoteAddr unless a trusted-proxy list validates the TCP peer before we read headers.
func trustedPathFromHeaders(trusted []*net.IPNet) bool {
	return len(trusted) > 0
}

func forwardedClientFromHeaders(req *http.Request) (ip string, source string, ok bool) {
	for _, header := range []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"} {
		v := strings.TrimSpace(req.Header.Get(header))
		if v == "" {
			continue
		}
		if strings.EqualFold(header, "X-Forwarded-For") {
			parts := strings.Split(v, ",")
			for _, part := range parts {
				if parsed := parseClientIPCandidate(part); parsed != "" {
					return parsed, strings.ToLower(header), true
				}
			}
			continue
		}
		if parsed := parseClientIPCandidate(v); parsed != "" {
			return parsed, strings.ToLower(header), true
		}
	}
	return "", "", false
}

func writeJSON(path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmpFile.Write(body); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	return nil
}

func fallbackString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return strings.TrimSpace(fallback)
	}
	return value
}
