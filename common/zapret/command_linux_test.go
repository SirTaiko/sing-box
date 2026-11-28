//go:build linux

package zapret

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Run this test binary with cap_net_admin,cap_net_raw+ep to exercise the same
// non-root launch as the desktop package. No routes or firewall are touched.
func TestNetworkCapabilitiesSurviveExec(t *testing.T) {
	if os.Getenv("MVPN_CAPABILITY_CHILD") == "1" {
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		if err := unix.Capget(&header, &caps[0]); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("effective=%x\n", caps[0].Effective)
		return
	}
	for _, engine := range []bool{false, true} {
		// Use an ordinary copy: the helper must not gain file capabilities on
		// its own, otherwise the regression would pass without ambient caps.
		path := t.TempDir() + "/child"
		content, err := os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, content, 0700); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(path, "-test.run=^TestNetworkCapabilitiesSurviveExec$")
		command.Env = append(os.Environ(), "MVPN_CAPABILITY_CHILD=1")
		if err = prepareNetworkCommand(command, engine); err != nil {
			t.Skip(err)
		}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v: %s", err, output)
		}
		mask := uint32(1 << unix.CAP_NET_ADMIN)
		if engine {
			mask |= 1 << unix.CAP_NET_RAW
		}
		if !strings.Contains(string(output), fmt.Sprintf("effective=%x\n", mask)) {
			t.Fatalf("unexpected child capabilities: %s", output)
		}
	}
}
