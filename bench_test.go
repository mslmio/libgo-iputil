package iputil

import (
	"net/netip"
	"testing"
)

// The bogon check sits on ip_api's request path, so its cost is per lookup.
func BenchmarkIsBogon(b *testing.B) {
	cases := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("fe80::1"),
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		IsBogon(cases[i%len(cases)])
	}
}
