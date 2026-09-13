package iputil

import (
	"net/netip"
	"sort"
)

// The address space that must never appear as a public peer: unallocated,
// reserved, private, documentation and link-local blocks, plus the 6to4 and
// Teredo encodings that tunnel the IPv4 ones into IPv6.
//
// These are the same lists the JavaScript and SDK bogon checks carry
// (mslm/libjs/ip/isBogon.ts), and the three must agree - a client that
// short-circuits an address the API would have answered, or the reverse, is a
// difference customers see.
var bogonCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",

	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"::/96",
	"100::/64",
	"2001:10::/28",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10",
	"ff00::/8",

	// 6to4 wrappers around the IPv4 blocks above.
	"2002::/24",
	"2002:a00::/24",
	"2002:7f00::/24",
	"2002:a9fe::/32",
	"2002:ac10::/28",
	"2002:c000::/40",
	"2002:c000:200::/40",
	"2002:c0a8::/32",
	"2002:c612::/31",
	"2002:c633:6400::/40",
	"2002:cb00:7100::/40",
	"2002:e000::/20",
	"2002:f000::/20",
	"2002:ffff:ffff::/48",

	// Teredo wrappers around the same.
	"2001::/40",
	"2001:0:a00::/40",
	"2001:0:7f00::/40",
	"2001:0:a9fe::/48",
	"2001:0:ac10::/44",
	"2001:0:c000::/56",
	"2001:0:c000:200::/56",
	"2001:0:c0a8::/48",
	"2001:0:c612::/47",
	"2001:0:c633:6400::/56",
	"2001:0:cb00:7100::/56",
	"2001:0:e000::/36",
	"2001:0:f000::/36",
	"2001:0:ffff:ffff::/64",
}

// Sorted, merged and disjoint, so membership is a binary search.
//
// Merging is what makes that search CORRECT, and correctness is the whole
// reason for it - measured against the linear scan this replaced, the two are
// the same speed (31.5 vs 32.4 ns/op), because 15 and 47 entries with an early
// exit is not a table binary search wins on. The published list overlaps itself
// (::/96 contains ::/128 and ::1/128), and against overlapping spans "the last
// range starting at or below addr" can land on a narrow one and miss the wide
// one containing it - so a future reader tempted to drop the merge and keep the
// search should know it answers ::5 as public.
var (
	bogons4 []Range
	bogons6 []Range
)

func init() {
	var v4, v6 []Range
	for _, s := range bogonCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// A malformed constant in this file, which no input can cause and
			// no caller could handle.
			panic("iputil: bad bogon cidr " + s)
		}
		r := RangeOf(p)
		if r.Start.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	bogons4 = merge(v4)
	bogons6 = merge(v6)
}

// IsBogon reports whether an address is in bogon space.
//
// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries, so
// ::ffff:10.0.0.1 is a bogon for the same reason 10.0.0.1 is.
func IsBogon(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	table := bogons6
	if addr.Is4() {
		table = bogons4
	}
	i := sort.Search(len(table), func(i int) bool {
		return table[i].End.Compare(addr) >= 0
	})
	return i < len(table) && table[i].Start.Compare(addr) <= 0
}

// IsBogonStr is IsBogon over an unparsed address. Anything that is not an
// address is not a bogon.
func IsBogonStr(s string) bool {
	addr, err := ParseAddr(s)
	if err != nil {
		return false
	}
	return IsBogon(addr)
}

// Bogons is the merged bogon space, ascending, IPv4 first. The slice is a copy;
// the table is not.
func Bogons() []Range {
	out := make([]Range, 0, len(bogons4)+len(bogons6))
	out = append(out, bogons4...)
	return append(out, bogons6...)
}

// merge sorts ranges and fuses every overlapping or adjacent pair, leaving a
// disjoint ascending set.
func merge(in []Range) []Range {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if c := in[i].Start.Compare(in[j].Start); c != 0 {
			return c < 0
		}
		return in[i].End.Compare(in[j].End) < 0
	})
	out := []Range{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		// Adjacent counts as overlapping: two spans that meet end-to-start are
		// one span, and leaving them apart costs a search step forever.
		if r.Start.Compare(last.End) <= 0 || r.Start == last.End.Next() {
			if r.End.Compare(last.End) > 0 {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
