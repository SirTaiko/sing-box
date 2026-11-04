//go:build linux

package desync

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func TestSource37EveryBoundQueueRequiresReceipt(t *testing.T) {
	for _, role := range []string{"out", "in", "icmp"} {
		for _, errno := range []unix.Errno{unix.ENODEV, unix.EPERM} {
			t.Run(role+"/"+errno.Error(), func(t *testing.T) {
				data := newFakeNFQueueConn("bound-receipt", 0, nil)
				seams := installLinuxCaptureSeams(t, data)
				lease := newFilteredICMPLease(t, 16620)
				if err := lease.StartCapture(); err != nil {
					t.Fatal(err)
				}
				c := lease.capture.(*linuxCapture)
				q := c.queue
				if role == "in" {
					q = c.inQueue
				}
				if role == "icmp" {
					q = c.icmpQueue
				}
				data.setExecuteHook(func(_ int, m netlink.Message) error {
					if queue, ok := noOpConfigQueue(m); ok && queue == q {
						return errno
					}
					return nil
				})
				if err := lease.Close(nil); err == nil {
					t.Fatal("MODEL: missing own receipt was ignored")
				}
				if err := lease.WaitCaptureRetired(); err == nil {
					t.Fatal("MODEL: missing receipt retired capture")
				}
				if lease.engine.ActiveLeases() != 1 || data.closings() != 0 || len(seams.kernel.boundQueues()) != 3 || countKernelEvents(seams.kernel, "unbind") != 0 {
					t.Fatal("MODEL: missing receipt released identity/charge")
				}
			})
		}
	}
}

// A free manifest snapshot is not an ownership receipt. Kernel BIND remains
// authoritative when an unrelated listener wins after the snapshot.
func TestSource37KernelBindRemainsAuthority(t *testing.T) {
	data := newFakeNFQueueConn("bind-race", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	foreign := newFakeNFQueueConn("foreign", 0x8000fffe, seams.kernel)
	_, lease := newLinuxCaptureLease(t, 16621)
	data.setExecuteHook(func(_ int, m netlink.Message) error {
		q, cmd, ok := parseNFQueueConfig(m)
		if ok && cmd == nfqCfgCmdBind && q == 16621 {
			return seams.kernel.control(foreign, q, nfqCfgCmdBind)
		}
		return nil
	})
	if err := lease.StartCapture(); err == nil {
		t.Fatal("MODEL: stale free snapshot bypassed BIND")
	}
	if err := lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if seams.kernel.owner(16621) != foreign || qnumLive(16621) || lease.engine.ActiveLeases() != 0 || data.closings() != 1 {
		t.Fatal("MODEL: failed pre-w BIND did not safely clean own reservation")
	}
}
