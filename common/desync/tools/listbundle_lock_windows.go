//go:build windows

package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/windows"
)

// refreshLock is the short-lived exclusive publication lock. LockFileEx is
// released by the operating system when the handle is closed or the process
// exits, so no permanent PID file has to be guessed or cleaned up.
type refreshLock struct {
	file *os.File
}

// acquireRefreshLock takes an exclusive lock on DIRECTORY/.refresh.lock. The
// Engine never acquires it.
func acquireRefreshLock(ctx context.Context, root string, clock MDigClock) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if clock == nil {
		clock = systemClock{}
	}
	lockPath := filepath.Join(root, listBundleLockName)
	if err := rejectAliasedLeaf(lockPath); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, E.Cause(err, "open publication lock")
	}
	for {
		overlapped := new(windows.Overlapped)
		lockErr := windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, overlapped,
		)
		if lockErr == nil {
			release := func() {
				unlockOverlapped := new(windows.Overlapped)
				_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, unlockOverlapped)
				_ = file.Close()
			}
			return release, nil
		}
		if !errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
			_ = file.Close()
			return nil, E.Cause(lockErr, "acquire publication lock")
		}
		if err = clock.Sleep(ctx, 5*time.Millisecond); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
}

// replaceFileAtomically replaces target with source through the native
// MoveFileEx primitive. A remove-then-rename fallback is deliberately not
// implemented: two visible names would not be atomic.
func replaceFileAtomically(source string, target string) error {
	sourceUTF16, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return E.Cause(err, "encode temporary path")
	}
	targetUTF16, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return E.Cause(err, "encode target path")
	}
	if err = windows.MoveFileEx(
		sourceUTF16,
		targetUTF16,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	); err != nil {
		return E.Cause(err, "replace ", filepath.Base(target))
	}
	return nil
}

// syncDirectory is provided by MOVEFILE_WRITE_THROUGH on Windows: opening a
// directory handle for FlushFileBuffers is not a supported user-mode operation.
func syncDirectory(_ string) error {
	return nil
}

// fileLinkCount reports the hardlink count of a final path through the native
// file information query, so Windows aliases are detected like on POSIX.
func fileLinkCount(filePath string) (uint64, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return 0, E.Cause(err, "inspect link count")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 1, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return 0, E.Cause(err, "open link count")
	}
	defer file.Close()
	var fileInfo windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &fileInfo); err != nil {
		return 0, E.Cause(err, "query link count")
	}
	return uint64(fileInfo.NumberOfLinks), nil
}
