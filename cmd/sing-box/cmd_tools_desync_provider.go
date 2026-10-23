package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/common/desync/tools"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

// Explicit provider list refresh and rollback commands.
//
// These commands are the only network-facing members of the offline tool group,
// and only when the operator supplies a remote request. They never load a
// configuration, never start the product, never create a daemon or scheduler and
// never install a shell hook. The library keeps every fetch/parse/publish step
// behind injected dependencies so tests never touch the network.

func init() {
	commandToolsDesync.AddCommand(
		newToolsDesyncListRefreshCommand(operatorProviderDependencies),
	)
}

// operatorProviderDependencies wires the real acquisition adapters. It is called
// only after an explicit request has been validated, and only the selected recipe
// is used to build the HTTPS client.
func operatorProviderDependencies(recipe tools.ProviderRecipe) tools.ProviderDependencies {
	return tools.ProviderDependencies{
		HTTP:     tools.NewProviderHTTPClient(recipe),
		Resolver: operatorResolver{},
		Clock:    tools.SystemProviderClock(),
	}
}

func newToolsDesyncListRefreshCommand(dependencies func(tools.ProviderRecipe) tools.ProviderDependencies) *cobra.Command {
	var (
		flagRequest  string
		flagRollback string
		flagOutput   string
	)
	command := &cobra.Command{
		Use:   "list-refresh",
		Short: "Acquire, normalize and atomically publish a provider list bundle",
		Long: `Acquire one pinned zapret v72.9 provider recipe, normalize and aggregate it,
then publish an immutable generation under --output-dir. The single commit point
is OUTPUT/current.json; every previous generation is preserved.

The request is a real local JSON file, not stdin, and no provider URL, argv,
shell, secret, token, auto-reload or schedule flag exists. Use --rollback to
republish a previously committed generation offline.`,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if flagOutput == "" {
				return E.New("list-refresh: --output-dir is required")
			}
			if flagRequest == "" && flagRollback == "" {
				return E.New("list-refresh: exactly one of --request or --rollback is required")
			}
			if flagRequest != "" && flagRollback != "" {
				return E.New("list-refresh: --request and --rollback are mutually exclusive")
			}
			if flagRollback != "" {
				receipt, err := tools.RollbackLists(commandContext(command), flagOutput, flagRollback)
				if err != nil {
					return err
				}
				return writeRefreshReceipt(command, receipt)
			}
			requestBytes, err := readProviderRequestFile(flagRequest)
			if err != nil {
				return err
			}
			request, err := tools.DecodeListRefreshRequest(requestBytes)
			if err != nil {
				return err
			}
			recipe, err := tools.LookupProviderRecipe(request.Provider)
			if err != nil {
				return err
			}
			var deps tools.ProviderDependencies
			if dependencies != nil {
				deps = dependencies(recipe)
			}
			receipt, err := tools.RefreshLists(commandContext(command), request, flagOutput, deps)
			if err != nil {
				return err
			}
			return writeRefreshReceipt(command, receipt)
		},
	}
	command.Flags().StringVar(&flagRequest, "request", "", "explicit desync.list-refresh/v1 request file")
	command.Flags().StringVar(&flagRollback, "rollback", "", "republish a previous 32 character generation offline")
	command.Flags().StringVar(&flagOutput, "output-dir", "", "operator owned bundle directory")
	return command
}

// readProviderRequestFile reads one explicit local request file. The request is
// never read from stdin and a symbolic link is refused.
func readProviderRequestFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, E.Cause(err, "list-refresh: inspect --request")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, E.New("list-refresh: --request must be a plain file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, E.Cause(err, "list-refresh: open --request")
	}
	defer file.Close()
	const maximum = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, E.Cause(err, "list-refresh: read --request")
	}
	if len(data) > maximum {
		return nil, E.New("list-refresh: --request exceeds 1 MiB")
	}
	return data, nil
}

func writeRefreshReceipt(command *cobra.Command, receipt tools.ListRefreshReceipt) error {
	encoder := json.NewEncoder(command.OutOrStdout())
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return E.Cause(err, "list-refresh: write receipt")
	}
	return nil
}

var _ = errors.Is
var _ = filepath.Base
