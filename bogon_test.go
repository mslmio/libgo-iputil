package iputil

import (
	"net/netip"
	"testing"
)

// Every published block must be bogon at both edges, and the addresses either
// side of it must not be. Membership alone is a weak assertion: a mask a bit
// too wide or too narrow still answers correctly for anything comfortably
// inside or outside, so the edges are the only cases that pin the width.
func TestBogonEdges(t *testing.T) {
	for _, cidr := range bogonCIDRs {
		p := netip.MustParsePrefix(cidr)
		r := RangeOf(p)

		if !IsBogon(r.Start) {
			t.Errorf("%s: first address %s not bogon", cidr, r.Start)
		}
		if !IsBogon(r.End) {
			t.Errorf("%s: last address %s not bogon", cidr, r.End)
		}
	}
}

// The overlapping entries are why the table is merged. ::/96 contains ::/128
// and ::1/128, so a binary search over the raw list can land on ::1/128 and
// report ::5 as public.
func TestBogonOverlapMerged(t *testing.T) {
	for _, s := range []string{"::5", "::", "::1", "::ffff:ffff"} {
		if !IsBogonStr(s) {
			t.Errorf("%s should be bogon (inside ::/96)", s)
		}
	}
	for i := 1; i < len(bogons6); i++ {
		if bogons6[i-1].End.Compare(bogons6[i].Start) >= 0 {
			t.Errorf("merged table still overlaps at %d: %s then %s",
				i, bogons6[i-1], bogons6[i])
		}
	}
	for i := 1; i < len(bogons4); i++ {
		if bogons4[i-1].End.Compare(bogons4[i].Start) >= 0 {
			t.Errorf("merged v4 table still overlaps at %d", i)
		}
	}
}

func TestBogonPublic(t *testing.T) {
	public := []string{
		"1.1.1.1", "8.8.8.8", "45.83.91.1", "9.255.255.255", "11.0.0.0",
		"100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0", "223.255.255.255",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::",
	}
	for _, s := range public {
		if IsBogonStr(s) {
			t.Errorf("%s wrongly reported as bogon", s)
		}
	}
}

// An IPv4-mapped address carries an IPv4 address and must be judged as one.
func TestBogonMapped(t *testing.T) {
	if !IsBogonStr("::ffff:10.0.0.1") {
		t.Error("::ffff:10.0.0.1 should be bogon: it is 10.0.0.1")
	}
	if IsBogonStr("::ffff:8.8.8.8") {
		t.Error("::ffff:8.8.8.8 should not be bogon: it is 8.8.8.8")
	}
}

func TestBogonNonAddr(t *testing.T) {
	for _, s := range []string{"", "nonsense", "10.0.0.0/8", "fe80::1%eth0"} {
		if IsBogonStr(s) {
			t.Errorf("%q is not an address and so not a bogon", s)
		}
	}
}

// The special-purpose blocks that are not globally reachable, unallocated IPv6,
// and the 6to4 and Teredo forms of every IPv4 block, each pinned at an edge,
// with the addresses just outside them that must stay public.
func TestBogonReservedAndUnallocated(t *testing.T) {
	for _, s := range []string{
		"192.88.99.2", "64:ff9b::808:808", "64:ff9b:1::1", "100:0:0:1::1", "2001:2::1",
		"3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "5f00::1",
		"2001:1::1", "2001:3::1", "2001:20::1", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
		"1000::1", "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::1", "e000::1",
		"2002:6440::1", "2001:0:6440::1", "2002:c058:6302::1", "2001:0:c058:6302::1",
	} {
		if !IsBogonStr(s) {
			t.Errorf("%s should be bogon", s)
		}
	}
	for _, s := range []string{
		"192.88.99.1", "192.88.99.3", "3fff:1000::", "2001:200::", "2000::1",
		"2001:0:808:808::1", "2002:808:808::1", "2002:6480::1", "2001:0:6480::1",
	} {
		if IsBogonStr(s) {
			t.Errorf("%s wrongly reported as bogon", s)
		}
	}
}
