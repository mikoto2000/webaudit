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

func TestIPClassificationPrefixBoundaries(t *testing.T) {
	for ip, want := range map[string]string{
		"100.63.255.255": "public", "100.64.0.0": "shared", "100.127.255.255": "shared", "100.128.0.0": "public",
		"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": "reserved", "2000::": "public", "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff": "public", "4000::": "reserved",
	} {
		if got := classifyIP(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %s != %s", ip, got, want)
		}
	}
}

func BenchmarkClassifyIP(b *testing.B) {
	for _, address := range []string{"8.8.8.8", "2606:4700::1111", "100.64.1.1"} {
		b.Run(address, func(b *testing.B) {
			ip := netip.MustParseAddr(address)
			b.ReportAllocs()
			for b.Loop() {
				classifyIP(ip)
			}
		})
	}
}
