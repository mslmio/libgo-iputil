# libgo-iputil

Address plumbing for Go command-line tools and services: parse what a user typed, expand it to addresses, and answer whether an address is a bogon.

```bash
go get github.com/mslmio/libgo-iputil
```

Everything speaks `net/netip`. An address is a `netip.Addr` whatever its family, so there is one `Range` type rather than a parallel IPv4 and IPv6 hierarchy.

## Reading input the way a CLI should

`Scan` and `WalkAddrs` read arguments, standard input and list files as one stream, so `tool 1.1.1.1 8.8.8.0/24 ips.txt` and `cat ips.txt | tool` are the same code path.

```go
err := iputil.WalkAddrs(os.Args[1:], iputil.ListOpts, func(addr netip.Addr) error {
    fmt.Println(addr)
    return nil
})
```

Nothing is materialized. A `0.0.0.0/0` argument calls the function 4.3 billion times and allocates nothing, so the caller sets the memory bound by deciding what to do with each address — return an error to stop early. `CollectAddrs` is the slice form and takes a mandatory limit, because the inputs people type routinely exceed memory.

An argument that parses as an address, range or CIDR is that; only an argument that parses as none of them is considered a filename. A file called `8.8.8.8` cannot shadow the address.

## Ranges

```go
r, err := iputil.ParseRange("10.0.0.1-10.0.0.9")  // or "10.0.0.1,10.0.0.9"
r.Count()                                          // *big.Int; a /64 is already 2^64
r.Prefixes()                                       // the exact CIDR cover
r.Contains(netip.MustParseAddr("10.0.0.5"))
```

Endpoints given out of order are swapped rather than rejected: `10.0.0.9-10.0.0.1` names the same five addresses either way.

## Bogons

```go
iputil.IsBogon(addr)      // netip.Addr
iputil.IsBogonStr("10.0.0.1")
iputil.Bogons()           // the merged table
```

Unallocated, reserved, private, documentation and link-local space, plus the 6to4 and Teredo encodings that tunnel the IPv4 blocks into IPv6. An IPv4-mapped address is judged as the IPv4 address it carries.

## Also

`ParsePrefix` refuses host bits — `net.ParseCIDR` silently masks `10.0.0.1/8` down to `10.0.0.0/8`, which reads as acceptance of something probably mistyped. `Masked` is how you ask for the correction instead. `Decimal`/`AddrFromDecimal` convert to and from integer form, and `IsASN`/`ASN` handle `AS15169`.

## License

MIT.
