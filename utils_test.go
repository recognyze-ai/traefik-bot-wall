package traefik_bot_wall

import (
	"net"
	"net/http"
	"testing"
)

func TestExtractClientIP_UntrustedPeerIgnoresSpoofedForwarded(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	tn, err := parseTrustedProxyNetworks([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	ip, src, tr := extractClientIP(req, tn)
	if ip != "203.0.113.7" || src != "remote_addr" || !tr {
		t.Fatalf("wanted direct peer 203.0.113.7, got ip=%q src=%q trusted=%v", ip, src, tr)
	}
}

func TestExtractClientIP_TrustedPeerUsesForwarded(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	tn, err := parseTrustedProxyNetworks([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	ip, src, tr := extractClientIP(req, tn)
	if ip != "198.51.100.10" || src != "x-forwarded-for" || !tr {
		t.Fatalf("wanted forwarded 198.51.100.10, got ip=%q src=%q trusted=%v", ip, src, tr)
	}
}

func TestExtractClientIP_LegacyNoTrustedListHonorsHeadersUntrustedPath(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:1"
	req.Header.Set("CF-Connecting-IP", "198.51.100.20")
	ip, src, tr := extractClientIP(req, nil)
	if ip != "198.51.100.20" || src != "cf-connecting-ip" || tr {
		t.Fatalf("legacy: want header IP with trustedPath=false, got ip=%q src=%q trusted=%v", ip, src, tr)
	}
}

func TestParseTrustedProxyNetworksBareIPv4(t *testing.T) {
	nets, err := parseTrustedProxyNetworks([]string{"192.168.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 || nets[0].String() != "192.168.0.1/32" {
		t.Fatalf("unexpected %v", nets[0])
	}
	if !nets[0].Contains(net.ParseIP("192.168.0.1")) {
		t.Fatal("expected membership")
	}
}
