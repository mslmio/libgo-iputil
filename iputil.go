// Package iputil is the address plumbing shared by Mslm's Go tools: parsing and
// classifying what a user typed, expanding it to addresses, and answering
// whether an address is a bogon.
//
// Everything here speaks net/netip. An address is a netip.Addr whatever its
// family, so there is one Range type rather than a parallel v4 and v6 hierarchy,
// and comparisons are a method call rather than hand-rolled 128-bit arithmetic.
//
// The entry points most callers want are Scan and WalkAddrs, which read
// arguments, stdin and files as one stream.
package iputil

import "errors"

var (
	// ErrNotAddr is returned when input is not an IP address.
	ErrNotAddr = errors.New("iputil: not an ip address")

	// ErrNotPrefix is returned when input is not a CIDR prefix.
	ErrNotPrefix = errors.New("iputil: not a cidr")

	// ErrNotRange is returned when input is not an IP range.
	ErrNotRange = errors.New("iputil: not an ip range")

	// ErrMixedFamily is returned when a range mixes IPv4 and IPv6 endpoints.
	ErrMixedFamily = errors.New("iputil: range mixes ipv4 and ipv6")

	// ErrBadInput is returned for input that is malformed in no more specific
	// way.
	ErrBadInput = errors.New("iputil: invalid input")
)
