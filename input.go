package iputil

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// Kind says what one token of input turned out to be.
type Kind int

const (
	// KindUnknown is a token that parsed as nothing this package recognizes.
	KindUnknown Kind = iota
	KindAddr
	KindPrefix
	KindRange
	KindASN
)

// Input is one classified token, with whichever typed field its Kind names
// already parsed. Text is always the token as written.
type Input struct {
	Text   string
	Kind   Kind
	Addr   netip.Addr
	Prefix netip.Prefix
	Range  Range
	ASN    uint32
}

// Opts controls where Scan looks for input.
//
// The zero value reads arguments only, which is the safe default: a command
// that did not ask for stdin should never block on a terminal.
type Opts struct {
	// Stdin reads standard input before the arguments, when it is a pipe or a
	// redirected file. A terminal is only read if Interactive is also set.
	Stdin bool
	// Files treats an argument naming a readable file as a list of tokens.
	Files bool
	// Interactive allows reading from a terminal, ending at the first blank
	// line, and prints a prompt saying so. Only for a command whose whole
	// purpose is to consume a list.
	Interactive bool
}

// ListOpts is the usual setting for a command that takes addresses: arguments,
// piped stdin and files, but no prompting.
var ListOpts = Opts{Stdin: true, Files: true}

// Classify parses one token without consulting the filesystem.
func Classify(s string) Input {
	in := Input{Text: s, Kind: KindUnknown}
	if addr, err := ParseAddr(s); err == nil {
		in.Kind, in.Addr = KindAddr, addr
		return in
	}
	if r, err := ParseRange(s); err == nil {
		in.Kind, in.Range = KindRange, r
		return in
	}
	if p, err := Masked(s); err == nil {
		in.Kind, in.Prefix = KindPrefix, p
		return in
	}
	if n, err := ASN(s); err == nil {
		in.Kind, in.ASN = KindASN, n
		return in
	}
	return in
}

// Scan reads every token from stdin and the argument list, in that order, and
// hands each to fn already classified.
//
// Ordering is deliberate and matches what a pipeline expects: piped input is
// the bulk of the work and arguments are the additions to it.
//
// An argument that parses as an address, range or CIDR is that, and only an
// argument that parses as none of them is considered a filename - so a file
// named "8.8.8.8" in the working directory cannot shadow the address.
func Scan(args []string, opts Opts, fn func(Input) error) error {
	if opts.Stdin {
		if err := scanStdin(opts, len(args) == 0, fn); err != nil {
			return err
		}
	}
	for _, arg := range args {
		in := Classify(arg)
		if in.Kind == KindUnknown && opts.Files && FileExists(arg) {
			if err := scanFile(arg, fn); err != nil {
				return err
			}
			continue
		}
		if err := fn(in); err != nil {
			return err
		}
	}
	return nil
}

// WalkAddrs expands everything Scan finds into individual addresses, in order.
//
// Nothing is materialized: a /8 argument calls fn 16.7 million times and
// allocates nothing, so the caller sets the memory bound by deciding what to do
// with each address. Tokens that parse as nothing are skipped, because a list
// file with a header line is a normal thing to be handed.
func WalkAddrs(args []string, opts Opts, fn func(netip.Addr) error) error {
	return Scan(args, opts, func(in Input) error {
		switch in.Kind {
		case KindAddr:
			return fn(in.Addr)
		case KindRange:
			return in.Range.All(fn)
		case KindPrefix:
			return RangeOf(in.Prefix).All(fn)
		default:
			return nil
		}
	})
}

// CollectAddrs is WalkAddrs into a slice, refusing to grow past limit.
//
// Pass a limit. The whole point of the streaming form above is that the inputs
// people type routinely exceed memory, and an unbounded collector next to it is
// the one that will be reached for by accident.
func CollectAddrs(args []string, opts Opts, limit int) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, 64)
	err := WalkAddrs(args, opts, func(addr netip.Addr) error {
		if len(out) >= limit {
			return fmt.Errorf("iputil: more than %d addresses in input", limit)
		}
		out = append(out, addr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanStdin reads standard input when there is something there to read.
func scanStdin(opts Opts, noArgs bool, fn func(Input) error) error {
	st, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	terminal := st.Mode()&os.ModeCharDevice != 0
	if terminal {
		// A terminal with arguments already given is someone running a normal
		// command, not someone about to type a list.
		if !opts.Interactive || !noArgs {
			return nil
		}
		fmt.Fprintln(os.Stderr, "reading input, one per line; end with a blank line")
		return scanLines(os.Stdin, true, fn)
	}
	return scanLines(os.Stdin, false, fn)
}

// scanFile reads a list file.
func scanFile(path string, fn func(Input) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return scanLines(f, false, fn)
}

// scanLines splits a reader into whitespace-separated tokens.
//
// Line-oriented rather than word-oriented so a blank line stays visible, which
// is the only way an interactive session can say it is finished.
func scanLines(r io.Reader, stopOnBlank bool, fn func(Input) error) error {
	sc := bufio.NewScanner(r)
	// A list line is short, but a file with no newline at all would otherwise
	// fail on the 64 KB default with "token too long", which reads like
	// corruption rather than formatting.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if stopOnBlank {
				return nil
			}
			continue
		}
		for _, tok := range strings.Fields(line) {
			if err := fn(Classify(tok)); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
