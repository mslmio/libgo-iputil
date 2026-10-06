//go:build !unix

package iputil

import "os"

// isDevNull is false here, where a stat carries no device number. os.SameFile
// is no substitute: on Windows a console and NUL both stat as a character
// device with no file ID, so it would take every console for NUL.
func isDevNull(os.FileInfo) bool {
	return false
}
