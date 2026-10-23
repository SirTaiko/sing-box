//go:build !windows

package main

import (
	"os"
	"syscall"
)

// openToolOutputFile opens an existing or new output without truncating it and
// without following a final-component symbolic link, so the identity of the
// opened descriptor can be checked before the file is truncated.
func openToolOutputFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
}

// verifyToolOutputHandle has no POSIX-specific work: O_NOFOLLOW already refuses
// a final-component symbolic link, and createToolFile rejects a non-regular
// opened descriptor before truncating.
func verifyToolOutputHandle(*os.File) error {
	return nil
}
