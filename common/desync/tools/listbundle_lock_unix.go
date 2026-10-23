//go:build !windows

package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// refreshLock is the short-lived exclusive publication lock. The descriptor is
// closed by the operating system when the process exits, so no stale PID file
// has to be guessed.
type refreshLock struct {
	file *os.File
}

// acquireRefreshLock takes an exclusive lock on DIRECTORY/.refresh.lock. It is a
// file-operation lock, never a runtime lock: the Engine never acquires it.
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
	lock := &refreshLock{file: file}
	_ = lock
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			release := func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}
			return release, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			_ = file.Close()
			return nil, E.Cause(err, "acquire publication lock")
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

// replaceFileAtomically replaces target with source through one same-directory
// rename, which is atomic on the supported POSIX file systems.
func replaceFileAtomically(source string, target string) error {
	if err := os.Rename(source, target); err != nil {
		return E.Cause(err, "replace ", filepath.Base(target))
	}
	return nil
}

// syncDirectory makes a rename durable on file systems that support it.
func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return E.Cause(err, "open directory for sync")
	}
	defer file.Close()
	if err = file.Sync(); err != nil {
		return E.Cause(err, "sync directory")
	}
	return nil
}

// fileLinkCount reports the hardlink count of a final path. Aliased live files
// must not be replaced silently.
func fileLinkCount(filePath string) (uint64, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return 0, E.Cause(err, "inspect link count")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 1, nil
	}
	return uint64(stat.Nlink), nil
}
