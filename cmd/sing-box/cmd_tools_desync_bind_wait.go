package main

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/spf13/cobra"
)

// bindWaitDocument is the strict input of `tools desync bind-wait`. It matches
// the listen binding type exactly; there is no generated command/config
// execution and no implicit profile.
type bindWaitDocument struct {
	Bindings []option.TCPListenBinding `json:"bindings"`
}

type bindWaitOutput struct {
	Bindings []bindWaitEndpoint `json:"bindings"`
}

type bindWaitEndpoint struct {
	Address   string `json:"address"`
	Interface string `json:"interface,omitempty"`
	IPVersion int    `json:"ip_version"`
}

// newToolsDesyncBindWaitCommand implements the source `--bind-wait-only`
// behavior: resolve the same bindings used by a TCP inbound and print the
// resolved endpoints. It never creates a listener, socket, core instance,
// capture engine or native driver. The interface source and clock are
// injectable for hermetic unit checks; nil selects the real enumeration.
func newToolsDesyncBindWaitCommand(source listener.TCPBindInterfaceSource, clock listener.TCPBindClock) *cobra.Command {
	command := &cobra.Command{
		Use:   "bind-wait",
		Short: "Resolve TCP listen bindings and exit without listening",
		Long: `Resolve the accepted tcp_listen_bindings schema (the same resolver used by a
TCP inbound startup) and print the selected endpoints as JSON. This command
waits only for the configured interface/address conditions. It creates no
listener, socket, capture engine, VPN, core instance or native driver, and it
never reads a sing-box configuration.`,
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			inputPath, err := command.Flags().GetString("input")
			if err != nil {
				return err
			}
			if inputPath == "" {
				return E.New("--input is required")
			}
			reader, closeInput, err := openToolInput(command, inputPath)
			if err != nil {
				return err
			}
			defer closeInput()
			content, err := io.ReadAll(io.LimitReader(reader, 1<<20))
			if err != nil {
				return E.Cause(err, "read bindings input")
			}
			var document bindWaitDocument
			if err = singjson.UnmarshalDisallowUnknownFields(content, &document); err != nil {
				return E.Cause(err, "parse bindings input")
			}
			if len(document.Bindings) == 0 {
				return E.New("bindings: at least one binding is required")
			}
			resolved, err := listener.ResolveTCPBindings(commandContext(command), document.Bindings, source, clock)
			if err != nil {
				return err
			}
			output := bindWaitOutput{Bindings: make([]bindWaitEndpoint, 0, len(resolved))}
			for _, binding := range resolved {
				output.Bindings = append(output.Bindings, bindWaitEndpoint{
					Address:   binding.Address.String(),
					Interface: binding.Interface,
					IPVersion: binding.IPVersion,
				})
			}
			encoded, err := json.Marshal(output)
			if err != nil {
				return err
			}
			var buffer bytes.Buffer
			buffer.Write(encoded)
			buffer.WriteByte('\n')
			_, err = command.OutOrStdout().Write(buffer.Bytes())
			return err
		},
	}
	command.Flags().String("input", "", "path to the strict {bindings:[...]} JSON document, or - for stdin")
	_ = command.MarkFlagRequired("input")
	return command
}
