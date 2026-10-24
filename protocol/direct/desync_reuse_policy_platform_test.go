package direct

import (
	"runtime"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
)

// TestSec371PacketListenerControlPlatform records which platform supplies the
// per-socket exclusive listener control. Windows must supply it because a
// SO_REUSEADDR sibling can join a non-exclusive UDP endpoint there; the Linux
// native path needs none because sharing requires both sockets to opt in, which
// the owned packet socket never does. Disabled and stream-only configurations
// never install it: the control is requested only for a packet-enabled engine.
func TestSec371PacketListenerControlPlatform(t *testing.T) {
	exclusiveControl := desync.PacketUDPListenerControl()
	if runtime.GOOS == "windows" {
		if exclusiveControl == nil {
			t.Fatal("windows packet listener has no exclusive-bind control")
		}
		return
	}
	if exclusiveControl != nil {
		t.Fatal("non-windows packet listener unexpectedly installs an exclusive-bind control")
	}
}
