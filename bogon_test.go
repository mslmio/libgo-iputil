package iputil

import (
	"net/netip"
	"os"
	"strings"
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

func TestBogonNonAddr(t *testing.T) {
	for _, s := range []string{"", "nonsense", "10.0.0.0/8", "fe80::1%eth0"} {
		if IsBogonStr(s) {
			t.Errorf("%q is not an address and so not a bogon", s)
		}
	}
}

// The answers github.com/mslmio/bogon-ip says every checker built on its list
// must give, IPv4-mapped addresses among them. Each goes through IsBogon too,
// since ParseAddr unmaps before IsBogonStr ever sees an address.
func TestBogonVectors(t *testing.T) {
	data, err := os.ReadFile("bogon-ip/vectors.tsv")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatal("bogon-ip/vectors.tsv holds no vectors")
	}
	for _, line := range lines[1:] {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Fatalf("bogon-ip/vectors.tsv: %q is not address, bogon, why", line)
		}
		want := f[1] == "true"
		if got := IsBogonStr(f[0]); got != want {
			t.Errorf("%s: IsBogonStr is %v, want %v (%s)", f[0], got, want, f[2])
		}
		if got := IsBogon(netip.MustParseAddr(f[0])); got != want {
			t.Errorf("%s: IsBogon is %v, want %v (%s)", f[0], got, want, f[2])
		}
	}
}
