package iputil

import (
	"net/netip"
	"testing"
)

func TestParseRange(t *testing.T) {
	cases := []struct {
		in         string
		ok         bool
		start, end string
	}{
		{"10.0.0.1-10.0.0.9", true, "10.0.0.1", "10.0.0.9"},
		{"10.0.0.1,10.0.0.9", true, "10.0.0.1", "10.0.0.9"},
		// Reversed endpoints name the same span; swapping beats refusing.
		{"10.0.0.9-10.0.0.1", true, "10.0.0.1", "10.0.0.9"},
		{"::1-::9", true, "::1", "::9"},
		{"10.0.0.1-10.0.0.1", true, "10.0.0.1", "10.0.0.1"},
		{"10.0.0.1-::1", false, "", ""},
		{"10.0.0.1-", false, "", ""},
		{"-10.0.0.1", false, "", ""},
		{"10.0.0.1", false, "", ""},
		{"10.0.0.0/8", false, "", ""},
		{"", false, "", ""},
	}
	for _, c := range cases {
		r, err := ParseRange(c.in)
		if c.ok != (err == nil) {
			t.Errorf("%q: ok=%v, err=%v", c.in, c.ok, err)
			continue
		}
		if !c.ok {
			continue
		}
		if r.Start.String() != c.start || r.End.String() != c.end {
			t.Errorf("%q: got %s, want %s-%s", c.in, r, c.start, c.end)
		}
	}
}

func TestRangeCount(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"10.0.0.0/24", "256"},
		{"10.0.0.0/32", "1"},
		{"0.0.0.0/0", "4294967296"},
		{"::/64", "18446744073709551616"},
		{"::/0", "340282366920938463463374607431768211456"},
	}
	for _, c := range cases {
		got := RangeOf(netip.MustParsePrefix(c.in)).Count().String()
		if got != c.want {
			t.Errorf("%s: count %s, want %s", c.in, got, c.want)
		}
	}
}

// The prefixes must cover the range exactly: nothing outside, nothing missing,
// and contiguous.
func TestRangePrefixesExact(t *testing.T) {
	for _, s := range []string{
		"10.0.0.1-10.0.0.9",
		"10.0.0.0-10.0.0.255",
		"1.2.3.4-5.6.7.8",
		"0.0.0.0-255.255.255.255",
		"192.168.1.1-192.168.1.1",
		"::1-::ff",
		"2001:db8::-2001:db8::ffff",
	} {
		r, err := ParseRange(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		ps := r.Prefixes()
		if len(ps) == 0 {
			t.Errorf("%s: no prefixes", s)
			continue
		}
		if RangeOf(ps[0]).Start != r.Start {
			t.Errorf("%s: starts at %s, want %s", s, RangeOf(ps[0]).Start, r.Start)
		}
		if RangeOf(ps[len(ps)-1]).End != r.End {
			t.Errorf("%s: ends at %s, want %s", s, RangeOf(ps[len(ps)-1]).End, r.End)
		}
		for i := 1; i < len(ps); i++ {
			if RangeOf(ps[i-1]).End.Next() != RangeOf(ps[i]).Start {
				t.Errorf("%s: gap between %s and %s", s, ps[i-1], ps[i])
			}
		}
	}
}

// A prefix must round-trip to itself, or Prefixes is splitting where it need
// not.
func TestRangePrefixesRoundTrip(t *testing.T) {
	for _, s := range []string{
		"10.0.0.0/8", "10.0.0.0/32", "0.0.0.0/0",
		"2001:db8::/32", "::/0", "::1/128",
	} {
		p := netip.MustParsePrefix(s)
		ps := RangeOf(p).Prefixes()
		if len(ps) != 1 || ps[0] != p {
			t.Errorf("%s: round-tripped to %v", s, ps)
		}
	}
}

func TestRangeAll(t *testing.T) {
	r, _ := ParseRange("10.0.0.1-10.0.0.4")
	var got []string
	if err := r.All(func(a netip.Addr) error {
		got = append(got, a.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// Iterating to the top of the family must terminate. Next() past the maximum
// returns the invalid zero Addr, so a loop that advances before checking spins
// or panics.
func TestRangeAllAtFamilyMax(t *testing.T) {
	r, err := ParseRange("255.255.255.253-255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	done := make(chan struct{})
	go func() {
		_ = r.All(func(netip.Addr) error { n++; return nil })
		close(done)
	}()
	<-done
	if n != 3 {
		t.Errorf("visited %d addresses, want 3", n)
	}
}

func TestRangeContainsAndOverlaps(t *testing.T) {
	r, _ := ParseRange("10.0.0.10-10.0.0.20")
	for _, s := range []string{"10.0.0.10", "10.0.0.15", "10.0.0.20"} {
		if !r.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be inside %s", s, r)
		}
	}
	for _, s := range []string{"10.0.0.9", "10.0.0.21", "::10"} {
		if r.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be outside %s", s, r)
		}
	}
	adjacent, _ := ParseRange("10.0.0.21-10.0.0.30")
	if r.Overlaps(adjacent) {
		t.Error("adjacent ranges do not overlap")
	}
	touching, _ := ParseRange("10.0.0.20-10.0.0.30")
	if !r.Overlaps(touching) {
		t.Error("ranges sharing an address overlap")
	}
	v6, _ := ParseRange("::1-::ff")
	if r.Overlaps(v6) {
		t.Error("ranges of different families cannot overlap")
	}
}
