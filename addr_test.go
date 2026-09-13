package iputil

import "testing"

func TestParsePrefixRejectsHostBits(t *testing.T) {
	// net.ParseCIDR masks this down silently; here it is an error, and Masked
	// is the way to ask for the correction.
	if _, err := ParsePrefix("10.0.0.1/8"); err == nil {
		t.Error("ParsePrefix should refuse host bits")
	}
	p, err := Masked("10.0.0.1/8")
	if err != nil || p.String() != "10.0.0.0/8" {
		t.Errorf("Masked = %v, %v; want 10.0.0.0/8", p, err)
	}
	if _, err := ParsePrefix("10.0.0.0/8"); err != nil {
		t.Errorf("ParsePrefix on canonical form: %v", err)
	}
}

func TestParseAddrRejectsZone(t *testing.T) {
	if _, err := ParseAddr("fe80::1%eth0"); err == nil {
		t.Error("a zoned address is only meaningful on its own host")
	}
}

// A v4-mapped address is unmapped on the way in, so it compares and formats as
// the v4 address it carries.
func TestParseAddrUnmaps(t *testing.T) {
	addr, err := ParseAddr("::ffff:1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if !addr.Is4() || addr.String() != "1.2.3.4" {
		t.Errorf("got %s (is4=%v), want 1.2.3.4", addr, addr.Is4())
	}
}

func TestIsASN(t *testing.T) {
	for _, s := range []string{"AS1", "as1", "AS15169", "aS15169"} {
		if !IsASN(s) {
			t.Errorf("%q should be an ASN", s)
		}
	}
	// Leading zeros and signs are rejected rather than normalized: an ASN is an
	// identifier, and "AS007" is not how anyone writes 7.
	for _, s := range []string{"AS", "A1", "AS-1", "AS 1", "ASfoo", "1", "", "AS007", "AS1.5"} {
		if IsASN(s) {
			t.Errorf("%q should not be an ASN", s)
		}
	}
	n, err := ASN("AS15169")
	if err != nil || n != 15169 {
		t.Errorf("ASN = %d, %v; want 15169", n, err)
	}
}
