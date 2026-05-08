package botwall

import (
	"fmt"
	"net"
	"strings"
)

// parseTrustedProxyNetworks converts CIDR strings (or bare IPs interpreted as host routes) into *net.IPNet.
func parseTrustedProxyNetworks(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		s := raw
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("trustedProxyCIDRs: invalid IP %q", raw)
			}
			if ip4 := ip.To4(); ip4 != nil {
				s = fmt.Sprintf("%s/32", ip4.String())
			} else {
				s = fmt.Sprintf("%s/128", ip.String())
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("trustedProxyCIDRs: %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func ipInAnyNet(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil || len(nets) == 0 {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// parsePeerIP returns the IP of the immediate TCP peer (RemoteAddr), or nil if it cannot be parsed.
func parsePeerIP(remoteAddr string) net.IP {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		return net.ParseIP(strings.Trim(host, "[]"))
	}
	return net.ParseIP(strings.Trim(remoteAddr, "[]"))
}
