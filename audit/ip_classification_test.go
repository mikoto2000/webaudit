package audit

import (
	"net/netip"
	"testing"
)

func TestIPClassificationWithoutDatabase(t *testing.T) {
	for ip, want := range map[string]string{"8.8.8.8": "public", "2606:4700::1111": "public", "172.16.0.1": "private", "192.168.1.1": "private", "fc00::1": "private", "127.9.9.9": "loopback", "::1": "loopback", "fe80::1": "link_local", "169.254.1.1": "link_local", "ff05::1": "multicast", "239.1.1.1": "multicast", "198.18.0.1": "reserved", "192.0.2.1": "reserved", "2001:db8::1": "reserved", "100.64.1.1": "shared", "::": "unspecified", "0.0.0.0": "unspecified", "invalid": "invalid"} {
		p, _ := netip.ParseAddr(ip)
		if got := classifyIP(p); got != want {
			t.Fatalf("%s: %s != %s", ip, got, want)
		}
	}
}
