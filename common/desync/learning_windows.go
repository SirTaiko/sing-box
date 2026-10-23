//go:build windows

package desync

import "os"

// openPrivateAppend opens or creates a log file. Windows has no O_NOFOLLOW;
// the symlink check is performed with Lstat by the caller and the file is
// created owner-private.
func openPrivateAppend(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
