package iputil

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
	}{
		{"8.8.8.8", KindAddr},
		{"2001:db8::1", KindAddr},
		{"8.8.8.0/24", KindPrefix},
		// Host bits set: still a CIDR to the classifier, so it routes to the
		// CIDR branch rather than being mistaken for a filename.
		{"8.8.8.1/24", KindPrefix},
		{"2001:db8::/32", KindPrefix},
		{"8.8.8.1-8.8.8.9", KindRange},
		{"8.8.8.1,8.8.8.9", KindRange},
		{"AS15169", KindASN},
		{"as15169", KindASN},
		{"AS", KindUnknown},
		{"ASfoo", KindUnknown},
		{"", KindUnknown},
		{"ips.txt", KindUnknown},
		{"8.8.8.8/33", KindUnknown},
		{"256.0.0.1", KindUnknown},
		{"fe80::1%eth0", KindUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.in).Kind; got != c.kind {
			t.Errorf("Classify(%q) = %v, want %v", c.in, got, c.kind)
		}
	}
}

func TestWalkAddrsArgs(t *testing.T) {
	var got []string
	err := WalkAddrs([]string{"1.1.1.1", "10.0.0.0/30", "8.8.8.1-8.8.8.2", "junk"},
		Opts{}, func(a netip.Addr) error {
			got = append(got, a.String())
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"1.1.1.1",
		"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
		"8.8.8.1", "8.8.8.2",
	}
	assertAddrs(t, got, want)
}

// An argument that parses as an address must never be treated as a filename,
// even when a file of that name exists beside it.
func TestArgBeatsFileOfSameName(t *testing.T) {
	dir := t.TempDir()
	shadow := filepath.Join(dir, "8.8.8.8")
	if err := os.WriteFile(shadow, []byte("1.1.1.1\n2.2.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	var got []string
	err := WalkAddrs([]string{"8.8.8.8"}, Opts{Files: true}, func(a netip.Addr) error {
		got = append(got, a.String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertAddrs(t, got, []string{"8.8.8.8"})
}

func TestWalkAddrsFile(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "ips.txt")
	// Several tokens per line, a blank line, and a header that parses as
	// nothing - all of which a handed-over list file really contains.
	body := "# addresses\n1.1.1.1 2.2.2.2\n\n10.0.0.0/31\n3.3.3.3\n"
	if err := os.WriteFile(list, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var got []string
	err := WalkAddrs([]string{list}, Opts{Files: true}, func(a netip.Addr) error {
		got = append(got, a.String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertAddrs(t, got, []string{"1.1.1.1", "2.2.2.2", "10.0.0.0", "10.0.0.1", "3.3.3.3"})
}

// Without Files set, a filename is just an unrecognized token.
func TestFilesOptRespected(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(list, []byte("1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := WalkAddrs([]string{list}, Opts{}, func(netip.Addr) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("read %d addresses with Files unset, want 0", n)
	}
}

// An error from fn stops the walk where it happened, which is what lets a
// caller bound an otherwise unbounded expansion.
func TestWalkAddrsStopsOnError(t *testing.T) {
	n := 0
	err := WalkAddrs([]string{"0.0.0.0/0"}, Opts{}, func(netip.Addr) error {
		n++
		if n == 5 {
			return os.ErrClosed
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected the error to surface")
	}
	if n != 5 {
		t.Errorf("stopped after %d, want 5", n)
	}
}

func TestCollectAddrsLimit(t *testing.T) {
	got, err := CollectAddrs([]string{"10.0.0.0/30"}, Opts{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d addresses, want 4", len(got))
	}
	if _, err := CollectAddrs([]string{"10.0.0.0/24"}, Opts{}, 10); err == nil {
		t.Error("expected the limit to be enforced")
	}
}

func assertAddrs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
