package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// listPathKey normalizes an already absolute and cleaned path into the identity
// key used by the list-normalize collision guard.
//
// POSIX paths are compared byte for byte. Windows compares paths
// case-insensitively and Win32 ignores trailing dots and spaces in a path
// component, so both lexical aliases are folded before the comparison. This is
// the cheap lexical guard for names that do not exist yet; filesystem identity
// (hard links, symbolic links, symlinked parents) is resolved separately by
// inspectToolPath.
func listPathKey(path string, windows bool) string {
	if !windows {
		return path
	}
	return foldWindowsPath(path)
}

// foldWindowsPath lower-cases a path and trims the trailing dots and spaces
// Win32 drops from each component. Forward slashes are accepted by Win32 as
// separators, so they are folded too. It never turns a non-empty component into
// an empty one, so an unusual component such as "..." is left untouched instead
// of creating a false collision.
func foldWindowsPath(path string) string {
	path = strings.ToLower(path)
	path = strings.ReplaceAll(path, "/", `\`)
	volume := ""
	rest := path
	if len(path) >= 2 && path[1] == ':' {
		volume = path[:2]
		rest = path[2:]
	}
	parts := strings.Split(rest, `\`)
	for index, part := range parts {
		trimmed := strings.TrimRight(part, " .")
		if trimmed != "" || part == "" {
			parts[index] = trimmed
		}
	}
	return volume + strings.Join(parts, `\`)
}

// rawToolPath makes an explicit path absolute without the lexical cleaning that
// filepath.Abs performs. The uncleaned spelling is required because the
// operating system resolves ".." after following a symbolic link, while
// filepath.Clean resolves it before: cleaning first would inspect a different
// file than the one that is later opened, truncated or renamed.
func rawToolPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	if filepath.VolumeName(path) != "" {
		// A Windows drive-relative path such as "C:name" is resolved against
		// the current directory of that drive. It has no unambiguous raw
		// interpretation here, so it is rejected instead of being guessed.
		return "", E.New("refusing ambiguous path ", path, ": a drive-relative path is not supported")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", E.Cause(err, "resolve current directory")
	}
	return workingDirectory + string(os.PathSeparator) + path, nil
}

// rejectAmbiguousToolPath refuses a path whose ".." component is resolved by
// the kernel after a symbolic link. For such a path the lexical interpretation
// used by filepath.Clean/Abs differs from the filesystem interpretation used by
// open and rename, so inspecting it and then acting on it would refer to two
// different objects. Explicit rejection is intentional: the command never
// silently rewrites an operator path to its cleaned spelling.
//
// A ".." is ambiguous only when the lexical prefix before it resolves through a
// symbolic link to a different directory. An ordinary ".." after a real
// directory, and any path without "..", keep their usual OS semantics and are
// accepted.
func rejectAmbiguousToolPath(path string) error {
	if path == "" || path == "-" {
		return nil
	}
	raw, err := rawToolPath(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(raw)
	rest := raw[len(volume):]
	if runtime.GOOS == "windows" {
		// Win32 accepts both separators; a forward slash cannot be part of a
		// Windows file name, so folding it is not ambiguous here.
		rest = strings.ReplaceAll(rest, "/", `\`)
	}
	prefix := volume + string(os.PathSeparator)
	for _, component := range strings.Split(rest, string(os.PathSeparator)) {
		if component == "" || component == "." {
			continue
		}
		if component != ".." {
			prefix = filepath.Join(prefix, component)
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(prefix)
		if resolveErr != nil {
			// A ".." behind a prefix that cannot be resolved has no safe raw
			// meaning; the operation would fail or act on an unexpected path.
			return E.Cause(resolveErr, "refusing ambiguous path ", path, ": cannot resolve ", prefix, " before \"..\"")
		}
		lexicalKey := listPathKey(filepath.Clean(prefix), runtime.GOOS == "windows")
		resolvedKey := listPathKey(filepath.Clean(resolved), runtime.GOOS == "windows")
		if lexicalKey != resolvedKey {
			return E.New("refusing ambiguous path ", path, ": \"..\" follows the symbolic link ", prefix, " which resolves to ", resolved, "; pass the resolved path instead")
		}
		prefix = filepath.Dir(prefix)
	}
	return nil
}

// toolPathSpec names one explicit path of a command. Write roles are refused
// when the final component is a symbolic link or a directory; every role takes
// part in the identity collision check.
type toolPathSpec struct {
	Role  string
	Path  string
	Write bool
}

// toolPath is the inspected identity of one explicit path. Info is the followed
// filesystem object when the path exists (os.SameFile resolves hard links and
// symbolic links); Canonical is the path with every existing prefix resolved and
// the same lexical folding as listPathKey, so absent targets reached through a
// symlinked parent still compare equal.
type toolPath struct {
	Role      string
	Path      string
	Write     bool
	Stream    bool
	Symlink   bool
	Directory bool
	Canonical string
	Info      os.FileInfo
}

// protectedToolFile is one already-open file a later write must not alias.
type protectedToolFile struct {
	Role string
	Info os.FileInfo
}

func inspectToolPaths(specs []toolPathSpec) ([]toolPath, error) {
	paths := make([]toolPath, 0, len(specs))
	for _, spec := range specs {
		path, err := inspectToolPath(spec)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func inspectToolPath(spec toolPathSpec) (toolPath, error) {
	entry := toolPath{Role: spec.Role, Path: spec.Path, Write: spec.Write}
	if spec.Path == "" || spec.Path == "-" {
		entry.Stream = true
		return entry, nil
	}
	if err := rejectAmbiguousToolPath(spec.Path); err != nil {
		return entry, err
	}
	absolute, err := filepath.Abs(spec.Path)
	if err != nil {
		return entry, E.Cause(err, "resolve ", spec.Role, " path")
	}
	entry.Canonical = absolute
	if lstat, lstatErr := os.Lstat(absolute); lstatErr == nil {
		entry.Symlink = lstat.Mode()&os.ModeSymlink != 0
		entry.Directory = lstat.IsDir()
	} else if !errors.Is(lstatErr, fs.ErrNotExist) {
		return entry, E.Cause(lstatErr, "inspect ", spec.Role, " path")
	}
	info, statErr := os.Stat(absolute)
	switch {
	case statErr == nil:
		entry.Info = info
		if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
			entry.Canonical = resolved
		}
		entry.Canonical = listPathKey(filepath.Clean(entry.Canonical), runtime.GOOS == "windows")
	case errors.Is(statErr, fs.ErrNotExist):
		entry.Canonical = resolveMissingToolPath(absolute)
	default:
		return entry, E.Cause(statErr, "inspect ", spec.Role, " path")
	}
	if spec.Write {
		if entry.Symlink {
			return entry, E.New("refusing to write through the symbolic link ", spec.Path)
		}
		if entry.Directory {
			return entry, E.New("refusing to write to the directory ", spec.Path)
		}
		if entry.Info != nil && !entry.Info.Mode().IsRegular() {
			return entry, E.New("refusing to write to the non-regular file ", spec.Path)
		}
	}
	return entry, nil
}

// resolveMissingToolPath resolves the deepest existing ancestor with
// filepath.EvalSymlinks and re-appends the missing components, so an absent
// target under a symlinked directory compares equal to the same target under the
// directory the link points at.
func resolveMissingToolPath(absolute string) string {
	remainder := ""
	current := absolute
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			if remainder != "" {
				resolved = filepath.Join(resolved, remainder)
			}
			return listPathKey(filepath.Clean(resolved), runtime.GOOS == "windows")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		if remainder == "" {
			remainder = filepath.Base(current)
		} else {
			remainder = filepath.Join(filepath.Base(current), remainder)
		}
		current = parent
	}
	return listPathKey(filepath.Clean(absolute), runtime.GOOS == "windows")
}

// checkToolPathCollisions rejects any two explicit paths that name the same
// filesystem object or the same lexical target. This runs before a command opens
// or truncates anything.
func checkToolPathCollisions(paths []toolPath) error {
	for left := 0; left < len(paths); left++ {
		if paths[left].Stream {
			continue
		}
		for right := left + 1; right < len(paths); right++ {
			if paths[right].Stream {
				continue
			}
			if toolPathsCollide(paths[left], paths[right]) {
				return E.New("refusing to use the ", paths[left].Role, " path and the ", paths[right].Role, " path for the same file: ", paths[right].Path)
			}
		}
	}
	return nil
}

func toolPathsCollide(left toolPath, right toolPath) bool {
	if left.Info != nil && right.Info != nil && os.SameFile(left.Info, right.Info) {
		return true
	}
	return left.Canonical == right.Canonical
}

// checkFileIdentity refuses to write to an open file that is already open under
// another role. It is called on the descriptor that is about to be truncated, so
// the check cannot be separated from the destructive step.
func checkFileIdentity(path string, info os.FileInfo, protected []protectedToolFile) error {
	if info == nil {
		return nil
	}
	for _, entry := range protected {
		if entry.Info == nil {
			continue
		}
		if os.SameFile(entry.Info, info) {
			return E.New("refusing to write ", path, ": it is the same file as the ", entry.Role, " file")
		}
	}
	return nil
}

// checkPathIdentity re-inspects a write target immediately before it is replaced
// and refuses when it now aliases one of the open input files. It narrows the
// window in which a concurrent writer of the same directory could swap the
// target; it is not a claim of crash-atomic publication.
func checkPathIdentity(path string, protected []protectedToolFile) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return E.Cause(err, "inspect output")
	}
	return checkFileIdentity(path, info, protected)
}
