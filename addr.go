package iputil

import (
	"net/netip"
	"strconv"
	"strings"
)

// ParseAddr parses a bare IP address.
//
// A zone ("fe80::1%eth0") is rejected: every caller here is asking about an
// address as a value to look up or compare, and a zone makes it meaningful only
// on the host that produced it.
func ParseAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, ErrNotAddr
	}
	return addr.Unmap(), nil
}

// ParsePrefix parses a CIDR prefix and requires it to be in canonical form,
// with every host bit clear.
//
// net.ParseCIDR silently masks "10.0.0.1/8" down to 10.0.0.0/8, which reads as
// acceptance of something the user probably mistyped. Masked reports the
// canonical form when a caller would rather correct than reject.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, ErrNotPrefix
	}
	if p.Addr().Zone() != "" || p.Masked() != p {
		return netip.Prefix{}, ErrNotPrefix
	}
	return p, nil
}

// Masked parses a CIDR prefix and clears any host bits rather than refusing.
func Masked(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, ErrNotPrefix
	}
	return p.Masked(), nil
}

// IsAddr reports whether s is a bare IP address.
func IsAddr(s string) bool {
	_, err := ParseAddr(s)
	return err == nil
}

// IsPrefix reports whether s is a CIDR prefix. Host bits are tolerated here,
// because this is the classifier the input scanner branches on and rejecting
// "10.0.0.1/8" would send it down the "unknown" path rather than the CIDR one.
func IsPrefix(s string) bool {
	_, err := Masked(s)
	return err == nil
}

// IsRange reports whether s is an IP range in either accepted spelling.
func IsRange(s string) bool {
	_, err := ParseRange(s)
	return err == nil
}

// IsASN reports whether s names an autonomous system, as "AS15169" or
// "as15169". The number must be a plain non-negative integer, so "AS-1" and
// "AS 15169" are not ASNs.
func IsASN(s string) bool {
	if len(s) < 3 {
		return false
	}
	if !strings.EqualFold(s[:2], "as") {
		return false
	}
	n, err := strconv.ParseUint(s[2:], 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == s[2:]
}

// ASN returns the number part of an ASN string.
func ASN(s string) (uint32, error) {
	if !IsASN(s) {
		return 0, ErrBadInput
	}
	n, err := strconv.ParseUint(s[2:], 10, 32)
	if err != nil {
		return 0, ErrBadInput
	}
	return uint32(n), nil
}
