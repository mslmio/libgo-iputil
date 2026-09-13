package iputil

import (
	"net/netip"
	"testing"
)

func TestDecimalRoundTrip(t *testing.T) {
	for _, s := range []string{
		"0.0.0.0", "1.2.3.4", "8.8.8.8", "255.255.255.255",
		"::1", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		addr := netip.MustParseAddr(s)
		forceV6 := !addr.Is4()
		back, err := AddrFromDecimal(Decimal(addr), forceV6)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if back != addr {
			t.Errorf("%s round-tripped to %s", s, back)
		}
	}
}

func TestDecimalKnownValues(t *testing.T) {
	if got := Decimal(netip.MustParseAddr("1.2.3.4")); got != "16909060" {
		t.Errorf("1.2.3.4 = %s, want 16909060", got)
	}
	if got := Decimal(netip.MustParseAddr("::1")); got != "1" {
		t.Errorf("::1 = %s, want 1", got)
	}
}

// A small number is IPv4 unless the caller says otherwise, which is what a
// caller converting a v4 column back wants.
func TestDecimalFamilyChoice(t *testing.T) {
	v4, err := AddrFromDecimal("1", false)
	if err != nil || v4.String() != "0.0.0.1" {
		t.Errorf("got %s, %v; want 0.0.0.1", v4, err)
	}
	v6, err := AddrFromDecimal("1", true)
	if err != nil || v6.String() != "::1" {
		t.Errorf("got %s, %v; want ::1", v6, err)
	}
}

func TestDecimalRejectsOutOfRange(t *testing.T) {
	for _, s := range []string{
		"-1", "", "abc", "0x10",
		"340282366920938463463374607431768211456", // 2^128
	} {
		if _, err := AddrFromDecimal(s, false); err == nil {
			t.Errorf("%q should be rejected", s)
		}
	}
}
