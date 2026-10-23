//go:build !windows

package desync

import (
	"os"
	"syscall"
)

// openPrivateAppend opens or creates a log file that must not be a symlink.
func openPrivateAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
}
