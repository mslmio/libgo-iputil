package iputil

import (
	"math/big"
	"net/netip"
	"strings"
)

// Range is an inclusive span of addresses of one family.
//
// Both endpoints are held rather than a prefix, because the ranges users type
// and the ranges registries publish are mostly not on a prefix boundary.
type Range struct {
	Start netip.Addr
	End   netip.Addr
}

// ParseRange parses "<start>-<end>" or "<start>,<end>".
//
// Endpoints given out of order are swapped rather than rejected: "10.0.0.9-10.0.0.1"
// names the same five addresses either way, and a user who typed it backwards
// wants those five, not an error.
func ParseRange(s string) (Range, error) {
	i := strings.IndexAny(s, "-,")
	if i <= 0 || i == len(s)-1 {
		return Range{}, ErrNotRange
	}
	start, err := ParseAddr(s[:i])
	if err != nil {
		return Range{}, ErrNotRange
	}
	end, err := ParseAddr(s[i+1:])
	if err != nil {
		return Range{}, ErrNotRange
	}
	return NewRange(start, end)
}

// NewRange builds a range from two addresses, ordering them.
func NewRange(start, end netip.Addr) (Range, error) {
	if !start.IsValid() || !end.IsValid() {
		return Range{}, ErrNotRange
	}
	if start.Is4() != end.Is4() {
		return Range{}, ErrMixedFamily
	}
	if start.Compare(end) > 0 {
		start, end = end, start
	}
	return Range{Start: start, End: end}, nil
}

// RangeOf is the span a prefix covers.
func RangeOf(p netip.Prefix) Range {
	p = p.Masked()
	return Range{Start: p.Addr(), End: lastOf(p)}
}

// Contains reports whether addr falls inside the range.
func (r Range) Contains(addr netip.Addr) bool {
	if addr.Is4() != r.Start.Is4() {
		return false
	}
	return r.Start.Compare(addr) <= 0 && r.End.Compare(addr) >= 0
}

// Overlaps reports whether two ranges share any address.
func (r Range) Overlaps(o Range) bool {
	if r.Start.Is4() != o.Start.Is4() {
		return false
	}
	return r.Start.Compare(o.End) <= 0 && o.Start.Compare(r.End) <= 0
}

// Count is how many addresses the range holds.
//
// A big.Int because an IPv6 range routinely exceeds uint64: a single /64 is
// already 2^64, and returning a saturated or wrapped count would be worse than
// the allocation.
func (r Range) Count() *big.Int {
	lo := new(big.Int).SetBytes(r.Start.AsSlice())
	hi := new(big.Int).SetBytes(r.End.AsSlice())
	return hi.Sub(hi, lo).Add(hi, big.NewInt(1))
}

// String renders the range in the hyphenated spelling.
func (r Range) String() string {
	return r.Start.String() + "-" + r.End.String()
}

// All iterates the range in ascending order, stopping early if fn returns an
// error.
//
// Nothing is materialized, so this is safe on a span no slice could hold - the
// caller decides when to stop.
func (r Range) All(fn func(netip.Addr) error) error {
	for addr := r.Start; ; addr = addr.Next() {
		if err := fn(addr); err != nil {
			return err
		}
		// Checked after the body so the final address is visited, and before
		// Next so a range ending at the family maximum terminates instead of
		// wrapping to the invalid zero Addr.
		if addr.Compare(r.End) >= 0 {
			return nil
		}
	}
}

// Prefixes is the smallest set of CIDR prefixes exactly covering the range.
//
// Greedy from the low end: at each step take the largest prefix that both
// starts at the current address and does not overrun the end. That is optimal
// here, and it is the same walk netipx.IPSet performs.
func (r Range) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	bits := r.Start.BitLen()
	addr := r.Start
	for {
		// Two limits, and the prefix is the tighter of them. Alignment caps how
		// wide it may be: a prefix wider than addr's trailing zero bits would
		// start below addr and take in addresses the range does not hold.
		size := bits - trailingZeros(addr)
		// The end caps it too, so narrow until the prefix stops overrunning.
		for size < bits && lastOf(netip.PrefixFrom(addr, size)).Compare(r.End) > 0 {
			size++
		}
		p := netip.PrefixFrom(addr, size)
		out = append(out, p)
		last := lastOf(p)
		if last.Compare(r.End) >= 0 {
			return out
		}
		addr = last.Next()
	}
}

// lastOf is the highest address in a prefix.
func lastOf(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i)%8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// trailingZeros counts the low zero bits of an address, which is how wide a
// prefix may be while still starting there.
func trailingZeros(addr netip.Addr) int {
	b := addr.AsSlice()
	n := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			for v := b[i]; v&1 == 0; v >>= 1 {
				n++
			}
			return n
		}
		n += 8
	}
	return n
}
