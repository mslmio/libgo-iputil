//go:build unix

package iputil

import (
	"os"
	"syscall"
)

// isDevNull reports whether st is the null device.
//
// It compares device numbers, not files: systemd's PrivateDevices=yes hands a
// service the host's /dev/null as stdin while the service sees its own.
func isDevNull(st os.FileInfo) bool {
	if st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	if err != nil {
		return false
	}
	a, ok := st.Sys().(*syscall.Stat_t)
	b, okNull := null.Sys().(*syscall.Stat_t)
	return ok && okNull && a.Rdev == b.Rdev
}
