package main

import (
	"io"
	"os"
	"time"

	"github.com/sagernet/sing-box/common/desync/tools"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

func newToolsDesyncMDigCommand(resolver tools.MDigResolver) *cobra.Command {
	var (
		flagFamily      string
		flagThreads     int
		flagEAgain      int
		flagEAgainDelay int
		flagVerbose     bool
		flagStats       int
		flagLogResolved string
		flagLogFailed   string
		flagInput       string
		flagOutput      string
	)
	command := &cobra.Command{
		Use:          "mdig",
		Short:        "Resolve a newline separated name list with the pinned mdig behavior",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			family, err := tools.ParseFamily(flagFamily)
			if err != nil {
				return E.Cause(err, "mdig")
			}
			if flagEAgainDelay < 0 {
				return E.New("mdig: --eagain-delay must not be negative")
			}
			// The pinned tool rejects zero values explicitly; the library treats
			// zero as "use the default", so the flag range is validated here.
			if flagThreads < 1 || flagThreads > 100 {
				return E.New("mdig: --threads must be within 1-100")
			}
			if flagEAgain < 1 || flagEAgain > 1000 {
				return E.New("mdig: --eagain must be within 1-1000")
			}
			// The library rejects these after the output has been opened; keep
			// the same cheap range checks in the command, before any path is
			// opened. mdigMaxEAgainDelay is 100 seconds in the library.
			if flagEAgainDelay > 100000 {
				return E.New("mdig: --eagain-delay must be within 0-100000 milliseconds")
			}
			if flagStats < 0 {
				return E.New("mdig: --stats must not be negative")
			}
			specs := []toolPathSpec{
				{Role: "input", Path: flagInput},
				{Role: "output", Path: flagOutput, Write: true},
				{Role: "resolved log", Path: flagLogResolved, Write: true},
				{Role: "failed log", Path: flagLogFailed, Write: true},
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
			protected := []protectedToolFile{{Role: "input", Info: toolInputInfo(input)}}
			output, closeOutput, err := openToolOutput(command, flagOutput, protected)
			if err != nil {
				return err
			}
			defer closeOutput()
			if outputFile, ok := output.(*os.File); ok {
				if info, statErr := outputFile.Stat(); statErr == nil {
					protected = append(protected, protectedToolFile{Role: "output", Info: info})
				}
			}
			var closers []func()
			resolvedLog, closeResolved, err := openMDigLog(flagLogResolved, protected)
			if err != nil {
				return err
			}
			if closeResolved != nil {
				closers = append(closers, closeResolved)
			}
			if resolvedFile, ok := resolvedLog.(*os.File); ok {
				if info, statErr := resolvedFile.Stat(); statErr == nil {
					protected = append(protected, protectedToolFile{Role: "resolved log", Info: info})
				}
			}
			failedLog, closeFailed, err := openMDigLog(flagLogFailed, protected)
			if err != nil {
				for _, closer := range closers {
					closer()
				}
				return err
			}
			if closeFailed != nil {
				closers = append(closers, closeFailed)
			}
			defer func() {
				for _, closer := range closers {
					closer()
				}
			}()
			_, err = tools.MDig(commandContext(command), input, output, command.ErrOrStderr(), resolver, nil, tools.MDigOptions{
				Family:         family,
				Threads:        flagThreads,
				EAgainAttempts: flagEAgain,
				EAgainDelay:    time.Duration(flagEAgainDelay) * time.Millisecond,
				Verbose:        flagVerbose,
				StatsEvery:     flagStats,
				LogResolved:    resolvedLog,
				LogFailed:      failedLog,
			})
			if err != nil {
				return err
			}
			return closeOutput()
		},
	}
	command.Flags().StringVar(&flagFamily, "family", "4", "address family: 4, 6 or both")
	command.Flags().IntVar(&flagThreads, "threads", 1, "resolver worker count (1-100)")
	command.Flags().IntVar(&flagEAgain, "eagain", 10, "attempts for a temporary resolver failure (1-1000)")
	command.Flags().IntVar(&flagEAgainDelay, "eagain-delay", 500, "delay between temporary failure attempts in milliseconds")
	command.Flags().BoolVar(&flagVerbose, "verbose", false, "print resolver progress to stderr")
	command.Flags().IntVar(&flagStats, "stats", 0, "print resolution statistics to stderr every N input lines")
	command.Flags().StringVar(&flagLogResolved, "log-resolved", "", "explicitly log resolved host names to this file")
	command.Flags().StringVar(&flagLogFailed, "log-failed", "", "explicitly log failed host names to this file")
	command.Flags().StringVar(&flagInput, "input", "-", "input path or - for stdin")
	command.Flags().StringVar(&flagOutput, "output", "-", "output path or - for stdout")
	return command
}

// openMDigLog opens an explicitly requested host name log. No log file is
// created unless the operator named one.
func openMDigLog(path string, protected []protectedToolFile) (writer io.Writer, closeFunc func(), err error) {
	if path == "" {
		return nil, nil, nil
	}
	file, err := createToolFile(path, protected)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}
