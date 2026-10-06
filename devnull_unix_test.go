//go:build unix

package iputil

import (
	"os"
	"syscall"
	"testing"
)

// A service or a container run without stdin gets /dev/null, a character
// device as a terminal is. It is neither prompted on, since the prompt lands in
// a log, nor read: nohup leaves it open for writing only.
func TestScanSkipsDevNull(t *testing.T) {
	cases := []struct {
		name string
		flag int
	}{
		{"redirected", os.O_RDONLY},
		{"nohup", os.O_WRONLY},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdin, err := os.OpenFile(os.DevNull, c.flag, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stderr, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			oldIn, oldErr := os.Stdin, os.Stderr
			os.Stdin, os.Stderr = stdin, stderr
			t.Cleanup(func() { os.Stdin, os.Stderr = oldIn, oldErr })

			n := 0
			err = Scan(nil, Opts{Stdin: true, Interactive: true}, func(Input) error { n++; return nil })
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if n != 0 {
				t.Errorf("read %d tokens, want 0", n)
			}
			if out, _ := os.ReadFile(stderr.Name()); len(out) != 0 {
				t.Errorf("printed %q, want nothing", out)
			}
		})
	}
}

// systemd's PrivateDevices=yes hands a service the host's /dev/null as stdin
// while the service sees a /dev/null of its own: another file, the same device.
func TestIsDevNullComparesDevices(t *testing.T) {
	null, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	other := *null.Sys().(*syscall.Stat_t)
	other.Dev++
	other.Ino++
	if !isDevNull(statWithSys{null, &other}) {
		t.Error("another file for the null device is not the null device")
	}
	other.Rdev++
	if isDevNull(statWithSys{null, &other}) {
		t.Error("another device is the null device")
	}
}

type statWithSys struct {
	os.FileInfo
	sys *syscall.Stat_t
}

func (s statWithSys) Sys() any { return s.sys }
