package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/desync/tools"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

// commandToolsDesync is the offline zapret support tool group. It is a child of
// the existing tools command and never creates a client, loads a configuration
// or touches the network on its own: every subcommand works on explicit local
// input or on the process standard streams.
var commandToolsDesync = &cobra.Command{
	Use:   "desync",
	Short: "Zapret-compatible offline and explicit provider/runtime tools",
	Long: `Tools derived from bol-van/zapret v72.9 (c849e55ef0f1c244206f5a05ff7b1ab41a3824ee).

Most commands are offline and never touch the network. Two entrypoints are
explicitly operator-invoked network/admin actions: list-refresh acquires provider
data only when the request says "acquisition": "remote", and reload/diagnostics
talk to an already running instance through its existing, safely configured
Clash controller using BOX_API_SECRET. None of them starts a service, schedules
anything, reads a configuration or starts a controller. Basic config-driven
desync works without the controller. Host names are only logged to explicitly
requested files. See docs/configuration/direct-desync-tools.md and
docs/configuration/direct-desync-providers.md for the exact contracts.`,
}

func init() {
	commandToolsDesync.AddCommand(
		newToolsDesyncIP2NetCommand(),
		newToolsDesyncMDigCommand(operatorResolver{}),
		newToolsDesyncDNSMakeQueryCommand(),
		newToolsDesyncDNSParseQueryCommand(),
		newToolsDesyncListNormalizeCommand(),
		newToolsDesyncBlockcheckReportCommand(),
		newToolsDesyncBindWaitCommand(nil, nil),
	)
	commandTools.AddCommand(commandToolsDesync)
}

func commandContext(command *cobra.Command) context.Context {
	if ctx := command.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// parseSingleFamily accepts only one address family, for the tools that operate
// on a single list family.
func parseSingleFamily(value string) (tools.Family, error) {
	family, err := tools.ParseFamily(value)
	if err != nil {
		return 0, err
	}
	if family == tools.FamilyIPv4|tools.FamilyIPv6 {
		return 0, E.New("a single address family is required, not both")
	}
	return family, nil
}

// openToolInput opens an explicit local path or returns the command input
// stream for "-".
func openToolInput(command *cobra.Command, path string) (io.Reader, func() error, error) {
	if path == "" || path == "-" {
		return command.InOrStdin(), func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, E.Cause(err, "open input")
	}
	return file, file.Close, nil
}

// toolInputInfo returns the opened input identity when the input is a real file,
// so a later output open can prove it is not the same object.
func toolInputInfo(reader io.Reader) os.FileInfo {
	file, ok := reader.(*os.File)
	if !ok {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return nil
	}
	return info
}

// openToolOutput opens an explicit local path or returns the command output
// stream for "-". The protected files are the already-open input roles.
func openToolOutput(command *cobra.Command, path string, protected []protectedToolFile) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return command.OutOrStdout(), func() error { return nil }, nil
	}
	file, err := createToolFile(path, protected)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}

// toolBeforeOutputOpen is an intentional test seam. It runs after the cheap
// final-component inspection and immediately before the output entry is
// acquired, so a regression test can replace the entry deterministically in the
// same window a concurrent writer would. Production keeps it as a no-op.
var toolBeforeOutputOpen = func(string) {}

// createToolFile refuses to follow a symbolic link and refuses to replace a
// directory, so an operator path cannot be redirected silently. The file is
// opened without O_TRUNC, the acquired object is checked again (on Windows a
// reparse point is refused through its handle), its descriptor is compared with
// the protected input files and only then truncated, so a check-then-truncate
// gap cannot destroy an input or follow a replaced final entry.
func createToolFile(path string, protected []protectedToolFile) (*os.File, error) {
	if err := rejectAmbiguousToolPath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, E.New("refusing to write through the symbolic link ", path)
		}
		if info.IsDir() {
			return nil, E.New("refusing to write to the directory ", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, E.Cause(err, "inspect output")
	}
	toolBeforeOutputOpen(path)
	file, err := openToolOutputFile(path)
	if err != nil {
		return nil, E.Cause(err, "create output")
	}
	if err = verifyToolOutputHandle(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, E.Cause(err, "inspect output")
	}
	if !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, E.New("refusing to write to the non-regular file ", path)
	}
	if err = checkFileIdentity(path, opened, protected); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err = file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, E.Cause(err, "truncate output")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, E.Cause(err, "seek output")
	}
	return file, nil
}

func newToolsDesyncIP2NetCommand() *cobra.Command {
	var (
		flagFamily       string
		flagPrefixLength string
		flagV4Threshold  string
		flagV6Threshold  string
		flagInput        string
		flagOutput       string
	)
	command := &cobra.Command{
		Use:          "ip2net",
		Short:        "Aggregate a newline separated address list into dense networks",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			family, err := parseSingleFamily(flagFamily)
			if err != nil {
				return E.Cause(err, "ip2net")
			}
			prefixMin, prefixMax, err := parsePrefixLengthFlag(flagPrefixLength)
			if err != nil {
				return E.Cause(err, "ip2net")
			}
			thresholdMul, thresholdDiv, err := parseV4ThresholdFlag(flagV4Threshold)
			if err != nil {
				return E.Cause(err, "ip2net")
			}
			thresholdV6, err := parseUint32(flagV6Threshold)
			if err != nil {
				return E.Cause(err, "ip2net: invalid --v6-threshold")
			}
			if thresholdV6 < 1 {
				return E.New("ip2net: --v6-threshold must be at least 1")
			}
			// The library rejects an out-of-range prefix pair, but only after
			// the output has been opened. Validate the same range here, before
			// any path is opened.
			if prefixMin != 0 || prefixMax != 0 {
				bits := 32
				if family == tools.FamilyIPv6 {
					bits = 128
				}
				if prefixMax >= bits {
					return E.New("ip2net: --prefix-length must be within 1-", bits-1)
				}
			}
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
			protected := []protectedToolFile{{Role: "input", Info: toolInputInfo(input)}}
			output, closeOutput, err := openToolOutput(command, flagOutput, protected)
			if err != nil {
				return err
			}
			defer closeOutput()
			_, err = tools.IP2Net(commandContext(command), input, output, tools.IP2NetOptions{
				Family:          family,
				PrefixLengthMin: prefixMin,
				PrefixLengthMax: prefixMax,
				V4ThresholdMul:  thresholdMul,
				V4ThresholdDiv:  thresholdDiv,
				V6Threshold:     thresholdV6,
			})
			if err != nil {
				return err
			}
			return closeOutput()
		},
	}
	command.Flags().StringVar(&flagFamily, "family", "4", "address family: 4 or 6")
	command.Flags().StringVar(&flagPrefixLength, "prefix-length", "", "prefix length min[-max] (default 22-30 for IPv4, 56-64 for IPv6)")
	command.Flags().StringVar(&flagV4Threshold, "v4-threshold", "3/4", "IPv4 density threshold as mul/div")
	command.Flags().StringVar(&flagV6Threshold, "v6-threshold", "5", "minimum number of IPv6 addresses in a subnet")
	command.Flags().StringVar(&flagInput, "input", "-", "input path or - for stdin")
	command.Flags().StringVar(&flagOutput, "output", "-", "output path or - for stdout")
	return command
}

// parsePrefixLengthFlag parses "min" or "min-max".
func parsePrefixLengthFlag(value string) (int, int, error) {
	if value == "" {
		return 0, 0, nil
	}
	minimum, maximum, found := strings.Cut(value, "-")
	parsedMin, err := parseNonNegativeInt(minimum)
	if err != nil {
		return 0, 0, E.New("invalid --prefix-length: ", value)
	}
	parsedMax := parsedMin
	if found {
		parsedMax, err = parseNonNegativeInt(maximum)
		if err != nil {
			return 0, 0, E.New("invalid --prefix-length: ", value)
		}
	}
	if parsedMin == 0 || parsedMax == 0 || parsedMax < parsedMin {
		return 0, 0, E.New("invalid --prefix-length: ", value)
	}
	return parsedMin, parsedMax, nil
}

// parseV4ThresholdFlag parses "mul/div" into the uint32 range the pinned
// sscanf("%u") accepts and enforces the upstream range validation
// (ip2net.c:286-301): 1 <= mul < div and div >= 2. The validation happens in
// the flag parser, before any input or output is opened, and an explicit zero
// is rejected here: only an omitted flag keeps the 3/4 default. The library
// zero value (IP2NetOptions{}) still means "use the default", so callers that
// do not use the command keep the previous API.
func parseV4ThresholdFlag(value string) (uint32, uint32, error) {
	invalid := func() (uint32, uint32, error) {
		return 0, 0, E.New("invalid --v4-threshold: ", value, " (need mul/div with 1 <= mul < div and div >= 2)")
	}
	multiplier, divisor, found := strings.Cut(value, "/")
	if !found {
		return invalid()
	}
	parsedMul, err := parseUint32(multiplier)
	if err != nil {
		return invalid()
	}
	parsedDiv, err := parseUint32(divisor)
	if err != nil {
		return invalid()
	}
	if parsedMul < 1 || parsedDiv < 2 || parsedMul >= parsedDiv {
		return invalid()
	}
	return parsedMul, parsedDiv, nil
}

func parseNonNegativeInt(value string) (int, error) {
	if value == "" {
		return 0, E.New("empty number")
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 31)
	if err != nil {
		return 0, err
	}
	return int(parsed), nil
}

// parseUint32 parses one unsigned 32-bit threshold, the range of the C
// sscanf("%u") conversions in ip2net.c:287 and ip2net.c:295.
func parseUint32(value string) (uint32, error) {
	if value == "" {
		return 0, E.New("empty number")
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func newToolsDesyncDNSMakeQueryCommand() *cobra.Command {
	var (
		flagName   string
		flagFamily string
		flagID     int
	)
	command := &cobra.Command{
		Use:          "dns-make-query",
		Short:        "Build the binary DNS query blob of the pinned mdig tool",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if flagName == "" {
				return E.New("dns-make-query: --name is required")
			}
			family, err := parseSingleFamily(flagFamily)
			if err != nil {
				return E.Cause(err, "dns-make-query")
			}
			var id uint16
			switch {
			case flagID < 0:
				var raw [2]byte
				if _, err = rand.Read(raw[:]); err != nil {
					return E.Cause(err, "dns-make-query: generate id")
				}
				id = binary.BigEndian.Uint16(raw[:])
			case flagID > 0xFFFF:
				return E.New("dns-make-query: --id must be within 0-65535")
			default:
				id = uint16(flagID)
			}
			message, err := tools.BuildDNSQuery(flagName, family, id)
			if err != nil {
				return err
			}
			return tools.WriteDNSQuery(command.OutOrStdout(), message)
		},
	}
	command.Flags().StringVar(&flagName, "name", "", "domain name to build the query for")
	command.Flags().StringVar(&flagFamily, "family", "4", "address family: 4 (A) or 6 (AAAA)")
	command.Flags().IntVar(&flagID, "id", -1, "deterministic DNS message id for tests (0-65535)")
	return command
}

func newToolsDesyncDNSParseQueryCommand() *cobra.Command {
	command := &cobra.Command{
		Use:          "dns-parse-query",
		Short:        "Extract A/AAAA addresses from a binary DNS response on stdin",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			message, err := tools.ReadDNSResponse(command.InOrStdin())
			if err != nil {
				return err
			}
			addresses, err := tools.ParseDNSResponse(message)
			if err != nil {
				return err
			}
			var builder strings.Builder
			for _, address := range addresses {
				builder.WriteString(address.String())
				builder.WriteByte('\n')
			}
			written, err := io.WriteString(command.OutOrStdout(), builder.String())
			if err != nil {
				return E.Cause(err, "dns-parse-query: write output")
			}
			if written != builder.Len() {
				return io.ErrShortWrite
			}
			return nil
		},
	}
	return command
}

// operatorResolver is the real operator resolver wiring. It is constructed as a
// value by the command registration and only performs a lookup when the operator
// explicitly runs the mdig command. The lookupNetIP field is nil in production,
// where the platform resolver is used; tests inject a synthetic lookup so the
// adapter classification and the real mdig consumer can be exercised without
// touching the network.
type operatorResolver struct {
	lookupNetIP func(ctx context.Context, network string, name string) ([]netip.Addr, error)
}

func (r operatorResolver) Lookup(ctx context.Context, name string, family tools.Family) ([]netip.Addr, error) {
	network := "ip"
	switch family {
	case tools.FamilyIPv4:
		network = "ip4"
	case tools.FamilyIPv6:
		network = "ip6"
	}
	lookup := r.lookupNetIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	addresses, err := lookup(ctx, network, name)
	if err != nil {
		return nil, classifyResolverLookupError(err)
	}
	return addresses, nil
}

// classifyResolverLookupError maps one platform resolver failure onto the mdig
// retry contract. mdig retries only the EAI_AGAIN analog, tools.ErrTemporary, and
// the platform reports temporary and timeout conditions as typed *net.DNSError
// values. The classification therefore has to keep the sentinel itself in the
// error chain, where the real consumer's errors.Is check sees it, not merely in
// the message text. E.Cause1 retains the original resolver error both in the
// diagnostic text and in the chain as well.
func classifyResolverLookupError(err error) error {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && (dnsError.IsTemporary || dnsError.IsTimeout) {
		return E.Cause1(err, tools.ErrTemporary)
	}
	return err
}
