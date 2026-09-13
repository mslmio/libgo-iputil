package iputil

import (
	"math/big"
	"net/netip"
)

// maxV4 is the largest IPv4 address as an integer, and the boundary AddrFromDecimal
// uses to choose a family.
var maxV4 = big.NewInt(0xffffffff)

// maxV6 is the largest IPv6 address as an integer.
var maxV6 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// Decimal renders an address as its integer value in base ten.
func Decimal(addr netip.Addr) string {
	return new(big.Int).SetBytes(addr.Unmap().AsSlice()).String()
}

// AddrFromDecimal parses a base-ten integer back into an address.
//
// A value that fits in 32 bits is read as IPv4 unless forceV6 is set, since
// that is what a caller converting a v4 table back wants. Above that it is
// IPv6, and above the v6 maximum it is an error.
func AddrFromDecimal(s string, forceV6 bool) (netip.Addr, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 {
		return netip.Addr{}, ErrBadInput
	}
	width := 16
	if !forceV6 && n.Cmp(maxV4) <= 0 {
		width = 4
	} else if n.Cmp(maxV6) > 0 {
		return netip.Addr{}, ErrBadInput
	}
	buf := make([]byte, width)
	n.FillBytes(buf)
	addr, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, ErrBadInput
	}
	return addr, nil
}
