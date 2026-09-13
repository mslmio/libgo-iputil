package iputil

import "os"

// FileExists reports whether path names an existing regular file.
//
// A directory is not a file here: the input scanner uses this to decide whether
// an argument it could not parse is a list to read, and opening a directory
// fails at read time with a message that names neither the argument nor the
// reason.
func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
