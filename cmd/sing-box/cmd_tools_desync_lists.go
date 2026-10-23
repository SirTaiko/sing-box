package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sagernet/sing-box/common/desync/tools"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

func newToolsDesyncListNormalizeCommand() *cobra.Command {
	var (
		flagKind     string
		flagInput    string
		flagOutput   string
		flagExclude  []string
		flagManifest string
	)
	command := &cobra.Command{
		Use:          "list-normalize",
		Short:        "Normalize and exclude entries of a local provider list snapshot",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			kind := tools.ListKind(flagKind)
			switch kind {
			case tools.ListKindDomain, tools.ListKindIP:
			default:
				return E.New("list-normalize: --kind must be domain or ip")
			}
			if flagManifest == "" {
				return E.New("list-normalize: --manifest is required")
			}
			if err := validateListPaths(flagInput, flagOutput, flagManifest, flagExclude); err != nil {
				return err
			}
			specs := []toolPathSpec{
				{Role: "input", Path: flagInput},
				{Role: "output", Path: flagOutput, Write: true},
				{Role: "manifest", Path: flagManifest, Write: true},
			}
			for _, path := range flagExclude {
				specs = append(specs, toolPathSpec{Role: "exclude", Path: path})
			}
			toolPaths, err := inspectToolPaths(specs)
			if err != nil {
				return err
			}
			if err = checkToolPathCollisions(toolPaths); err != nil {
				return err
			}
			input, closeInput, err := openToolInput(command, flagInput)
			if err != nil {
				return err
			}
			defer closeInput()
			protectedInputs := []protectedToolFile{{Role: "input", Info: toolInputInfo(input)}}
			excludeInputs := make([]tools.ListInput, 0, len(flagExclude))
			var excludeClosers []func()
			defer func() {
				for _, closer := range excludeClosers {
					closer()
				}
			}()
			for _, path := range flagExclude {
				if path == "" || path == "-" {
					return E.New("list-normalize: --exclude requires a local file")
				}
				excludeFile, openErr := openExclude(path)
				if openErr != nil {
					return openErr
				}
				excludeClosers = append(excludeClosers, func() { _ = excludeFile.Close() })
				if info, statErr := excludeFile.Stat(); statErr == nil {
					protectedInputs = append(protectedInputs, protectedToolFile{Role: "exclude", Info: info})
				}
				excludeInputs = append(excludeInputs, tools.ListInput{Path: path, Reader: excludeFile})
			}
			// Stage the manifest first and the list second. Neither staged file
			// is visible under the operator path until both have been written.
			manifestStage, err := newStagedPublication(flagManifest)
			if err != nil {
				return err
			}
			defer manifestStage.abort()
			outputWriter := io.Writer(command.OutOrStdout())
			var outputStage *stagedPublication
			if flagOutput != "" && flagOutput != "-" {
				outputStage, err = newStagedPublication(flagOutput)
				if err != nil {
					return err
				}
				defer outputStage.abort()
				outputWriter = outputStage.file
			}
			manifest, err := tools.NormalizeList(commandContext(command), tools.ListInput{Path: flagInput, Reader: input}, outputWriter, excludeInputs, tools.ListNormalizeOptions{Kind: kind})
			if err != nil {
				return err
			}
			if err = tools.WriteListManifest(manifestStage.file, manifest); err != nil {
				return err
			}
			// Re-inspect the destinations right before publication so a target
			// that became an alias of an open input is refused instead of
			// replaced. Streaming stdout has no rollback boundary.
			if err = checkPathIdentity(flagManifest, protectedInputs); err != nil {
				return err
			}
			if outputStage != nil {
				if err = checkPathIdentity(flagOutput, protectedInputs); err != nil {
					return err
				}
				if err = outputStage.commit(); err != nil {
					return E.Cause(err, "list-normalize: publish output")
				}
			}
			if err = manifestStage.commit(); err != nil {
				if outputStage != nil {
					return E.Cause(err, "list-normalize: output list was published but the manifest was not")
				}
				return E.Cause(err, "list-normalize: manifest could not be published")
			}
			return nil
		},
	}
	command.Flags().StringVar(&flagKind, "kind", "", "list kind: domain or ip")
	command.Flags().StringVar(&flagInput, "input", "-", "local snapshot path or - for stdin")
	command.Flags().StringVar(&flagOutput, "output", "-", "output path or - for stdout")
	command.Flags().StringArrayVar(&flagExclude, "exclude", nil, "local exclusion list path (repeatable)")
	command.Flags().StringVar(&flagManifest, "manifest", "", "provenance manifest output path (required)")
	return command
}

// stagedPublication writes one explicit output to a temporary file in the same
// directory and renames it into place on commit. Replacing the destination with
// a rename avoids opening the operator target with O_TRUNC, so a failed import
// leaves an existing last-good file untouched and does not create a new one.
type stagedPublication struct {
	path      string
	file      *os.File
	committed bool
}

func newStagedPublication(path string) (*stagedPublication, error) {
	if err := rejectAmbiguousToolPath(path); err != nil {
		return nil, err
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, E.Cause(err, "create staged output for ", path)
	}
	return &stagedPublication{path: path, file: file}, nil
}

// abort removes the staged file. It is safe to call after commit.
func (s *stagedPublication) abort() {
	if s == nil || s.committed {
		return
	}
	_ = s.file.Close()
	_ = os.Remove(s.file.Name())
}

func (s *stagedPublication) commit() error {
	name := s.file.Name()
	if err := s.file.Chmod(0o644); err != nil {
		s.abort()
		return E.Cause(err, "set output mode")
	}
	if err := s.file.Close(); err != nil {
		s.abort()
		return E.Cause(err, "close staged output")
	}
	if err := os.Rename(name, s.path); err != nil {
		_ = os.Remove(name)
		return E.Cause(err, "replace ", s.path)
	}
	s.committed = true
	return nil
}

// openExclude opens a regular exclusion file. The regular-file check happens
// before the open so an explicit FIFO cannot block the command, and is repeated
// on the opened descriptor.
func openExclude(path string) (*os.File, error) {
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, E.New("exclusion list is not a regular file: ", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, E.Cause(err, "open exclusion list")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, E.Cause(err, "open exclusion list")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, E.Cause(err, "inspect exclusion list")
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, E.New("exclusion list is not a regular file: ", path)
	}
	return file, nil
}

// validateListPaths rejects an output or manifest path that would overwrite an
// input, an exclusion list or the other output. This is the cheap lexical guard;
// the command additionally resolves filesystem identity before opening anything.
func validateListPaths(input string, output string, manifest string, excludes []string) error {
	return validateListPathsPlatform(input, output, manifest, excludes, runtime.GOOS == "windows")
}

// validateListPathsPlatform is the platform-parameterized form: on Windows the
// identity key folds case and Win32's ignored trailing dots/spaces, so an
// output alias of an input is rejected even though the byte strings differ.
// windows=false is the POSIX byte-exact comparison.
func validateListPathsPlatform(input string, output string, manifest string, excludes []string, windows bool) error {
	seen := make(map[string]string, len(excludes)+3)
	add := func(role string, path string) error {
		if path == "" || path == "-" {
			return nil
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return E.Cause(err, "resolve ", role, " path")
		}
		absolute = listPathKey(filepath.Clean(absolute), windows)
		if previous, found := seen[absolute]; found {
			return E.New("list-normalize: ", role, " path collides with the ", previous, " path: ", path)
		}
		seen[absolute] = role
		return nil
	}
	if err := add("input", input); err != nil {
		return err
	}
	if err := add("output", output); err != nil {
		return err
	}
	if err := add("manifest", manifest); err != nil {
		return err
	}
	for _, path := range excludes {
		if err := add("exclude", path); err != nil {
			return err
		}
	}
	return nil
}

func newToolsDesyncBlockcheckReportCommand() *cobra.Command {
	var (
		flagInput  string
		flagOutput string
	)
	command := &cobra.Command{
		Use:          "blockcheck-report",
		Short:        "Validate and normalize an offline desync.blockcheck/v1 result document",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			toolPaths, err := inspectToolPaths([]toolPathSpec{
				{Role: "input", Path: flagInput},
				{Role: "output", Path: flagOutput, Write: true},
			})
			if err != nil {
				return err
			}
			if err = checkToolPathCollisions(toolPaths); err != nil {
				return err
			}
			input, closeInput, err := openToolInput(command, flagInput)
			if err != nil {
				return err
			}
			defer closeInput()
			data, err := io.ReadAll(io.LimitReader(input, 4<<20+1))
			if err != nil {
				return E.Cause(err, "blockcheck-report: read input")
			}
			normalized, _, err := tools.NormalizeBlockcheckReportData(data)
			if err != nil {
				return err
			}
			protected := []protectedToolFile{{Role: "input", Info: toolInputInfo(input)}}
			output, closeOutput, err := openToolOutput(command, flagOutput, protected)
			if err != nil {
				return err
			}
			defer closeOutput()
			written, err := output.Write(normalized)
			if err != nil {
				return E.Cause(err, "blockcheck-report: write output")
			}
			if written != len(normalized) {
				return io.ErrShortWrite
			}
			return closeOutput()
		},
	}
	command.Flags().StringVar(&flagInput, "input", "-", "result document path or - for stdin")
	command.Flags().StringVar(&flagOutput, "output", "-", "normalized output path or - for stdout")
	return command
}
