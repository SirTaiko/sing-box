//go:build linux

package zapret

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// File capabilities on sing-box do not survive exec of nft/nfqws2. Pass only
// the network capabilities already permitted to this thread through ambient
// capabilities. This does not grant additional privileges or require root.
func prepareNetworkCommand(command *exec.Cmd, engine bool) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return fmt.Errorf("zapret: read capabilities for child: %w", err)
	}
	required := []uintptr{unix.CAP_NET_ADMIN}
	if engine {
		required = append(required, unix.CAP_NET_RAW)
	}
	for _, capability := range required {
		if caps[capability/32].Permitted&(1<<(capability%32)) == 0 {
			return fmt.Errorf("zapret: child requires network capability %d; install sing-box with cap_net_admin,cap_net_raw+ep", capability)
		}
	}
	command.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: required}
	return nil
}
