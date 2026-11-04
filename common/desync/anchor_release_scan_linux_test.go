//go:build linux

package desync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exercise the actual Lease.Close -> linuxCapture.retire -> observeReleaseScan
// composition. Only the native transport/report boundaries are modeled. The
// foreign row is installed AFTER the owning socket closes, not before drain.
func TestAnchorReleaseScanActualRetirement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		errno     unix.Errno
		report    string
		badReply  bool
		wantError string
	}{
		{name: "absent-ENODEV", errno: unix.ENODEV},
		{name: "different-port-EPERM", errno: unix.EPERM, report: "replacement"},
		{name: "different-port-ENODEV-race", errno: unix.ENODEV, report: "replacement"},
		{name: "different-port-independent-of-query-parser", errno: unix.ENODEV, report: "replacement", badReply: true},
		{name: "same-port-EPERM", errno: unix.EPERM, report: "old", wantError: "old queue instance still present"},
		{name: "same-port-ENODEV", errno: unix.ENODEV, report: "old", wantError: "old queue instance still present"},
		{name: "absent-EPERM", errno: unix.EPERM, wantError: "absence query did not qualify"},
		{name: "wrong-qnum-EPERM", errno: unix.EPERM, report: "wrong-queue", wantError: "absence query did not qualify"},
		{name: "duplicate-replacement", errno: unix.EPERM, report: "duplicate", wantError: "duplicate NFQUEUE report rows"},
		{name: "old-and-replacement", errno: unix.ENODEV, report: "inconsistent", wantError: "duplicate NFQUEUE report rows"},
		{name: "truncated-replacement", errno: unix.EPERM, report: "truncated", wantError: "malformed NFQUEUE report row"},
		{name: "unknown-replacement-mode", errno: unix.EPERM, report: "unknown-mode", wantError: "malformed NFQUEUE report row"},
		{name: "junk-after-replacement", errno: unix.EPERM, report: "junk", wantError: "malformed NFQUEUE report row"},
		{name: "read-failure-ENODEV", errno: unix.ENODEV, report: "unreadable", wantError: "fresh NFQUEUE report read"},
		{name: "read-failure-EPERM", errno: unix.EPERM, report: "unreadable", wantError: "fresh NFQUEUE report read"},
		{name: "absent-malformed-query", errno: unix.ENODEV, badReply: true, wantError: "absence query did not qualify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := newFakeNFQueueConn("release-scan", 0, nil)
			seams := installLinuxCaptureSeams(t, data)
			engine, lease := newLinuxCaptureLease(t, 16335)
			if err := lease.StartCapture(); err != nil {
				t.Fatal(err)
			}
			capture := lease.capture.(*linuxCapture)
			owner := capture.owner
			key := captureKey(owner.token, capture.anchor.capture)
			before := modelCaptureRecords(t, seams, FamilyIPv4)[key]
			if before == nil || before.port == nil {
				t.Fatal("missing witnessed capture")
			}
			queries := 0
			var reportBytes []byte
			previous := sendNetlinkRaw
			sendNetlinkRaw = func(session anchorSession, request []byte) error {
				if data.closings() != 1 {
					return fmt.Errorf("lookup before owning socket release")
				}
				if len(request) != 20 || binary.NativeEndian.Uint16(request[4:]) != uint16(unix.NFNL_SUBSYS_QUEUE<<8)|nfqMessageConfig ||
					binary.NativeEndian.Uint16(request[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_ACK ||
					binary.BigEndian.Uint16(request[18:]) != capture.queue || session.boundPort()&nftQueuePortBit != 0 {
					return fmt.Errorf("not an exact control-class no-attribute query: %x", request)
				}
				queries++
				old := queueReportRow(capture.queue, capture.outPort, 0)
				replaced := queueReportRow(capture.queue, capture.outPort+1, 3)
				report := ""
				switch tc.report {
				case "replacement":
					report = replaced
				case "old":
					report = old
				case "wrong-queue":
					report = queueReportRow(capture.queue+1, capture.outPort+1, 3)
				case "duplicate":
					report = replaced + "\n" + replaced
				case "inconsistent":
					report = old + "\n" + replaced
				case "truncated":
					report = fmt.Sprintf("%d %d 3 2 65531 0 0 0", capture.queue, capture.outPort+1)
				case "unknown-mode":
					report = fmt.Sprintf("%d %d 3 3 65531 0 0 0 1", capture.queue, capture.outPort+1)
				case "junk":
					report = replaced + "\ngarbage\n"
				case "unreadable":
					// A directory deterministically fails ReadFile, even as root.
					namespaceQueueReportPath = t.TempDir()
				}
				reportBytes = []byte(report)
				if tc.report != "unreadable" {
					if err := os.WriteFile(namespaceQueueReportPath, reportBytes, 0o600); err != nil {
						return err
					}
				}
				reply, err := fakeQueueAbsenceReply(request, session.boundPort())
				if err != nil {
					return err
				}
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(tc.errno))
				if tc.badReply {
					reply = reply[:len(reply)-1]
				}
				session.(*fakeAnchorSession).setRawReply(reply, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
				return nil
			}
			t.Cleanup(func() { sendNetlinkRaw = previous })
			closeErr := lease.Close(nil)
			if queries != 1 {
				t.Fatalf("release scan queries = %d, want 1", queries)
			}
			records := modelCaptureRecords(t, seams, FamilyIPv4)
			if tc.wantError == "" {
				if closeErr != nil || !capture.retired.Load() || len(records) != 0 || engine.ActiveLeases() != 0 {
					t.Fatalf("independent release-scan receipt rejected: Close=%v retired=%v metadata=%d charge=%d", closeErr, capture.retired.Load(), len(records), engine.ActiveLeases())
				}
				if err := lease.WaitCaptureRetired(); err != nil {
					t.Fatal(err)
				}
			} else {
				if closeErr == nil || !strings.Contains(closeErr.Error(), tc.wantError) {
					t.Fatalf("Close=%v, want %q", closeErr, tc.wantError)
				}
				retained := records[key]
				if capture.retired.Load() || engine.ActiveLeases() != 1 || !owner.retainedState() || len(records) != 1 || retained == nil || retained.port == nil || retained.record != before.record || retained.port.record != before.port.record {
					t.Fatalf("unqualified receipt lost exact owner/port/metadata/charge: %#v", records)
				}
				if err := lease.WaitCaptureRetired(); err == nil {
					t.Fatal("unqualified observation published a positive receipt")
				}
				_, second := newLinuxCaptureLease(t, 16337)
				if err := second.StartCapture(); err == nil {
					t.Fatal("new capture admitted over retained owner")
				}
				if seams.extraConnections() != 0 {
					t.Fatal("refused open created a new native generation")
				}
			}
			// Repeated Close returns the same terminal result; it must not replay
			// queries, verdicts or UNBIND the now-foreign witness.
			if again := lease.Close(nil); (again == nil) != (closeErr == nil) || (again != nil && again.Error() != closeErr.Error()) {
				t.Fatalf("repeated Close=%v, first=%v", again, closeErr)
			}
			if queries != 1 || data.closings() != 1 || countQueueCommand(t, data.executedMessages(), capture.queue, 2) != 0 || len(data.sentMessages()) != 0 {
				t.Fatal("retirement retried a socket close/query or sent a foreign UNBIND/verdict")
			}
			if tc.report != "unreadable" {
				after, err := os.ReadFile(namespaceQueueReportPath)
				if err != nil || string(after) != string(reportBytes) {
					t.Fatalf("report/foreign instance mutated: %q %v", after, err)
				}
			}
		})
	}
}

// A slow observation cannot turn the caller's 2s bound into successful native
// retirement. The existing teardown owner completes after the fresh row arrives;
// no retry worker, forced close, or new generation is needed.
func TestAnchorReleaseScanBoundedCloseKeepsOwner(t *testing.T) {
	data := newFakeNFQueueConn("bounded-release-scan", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 16339)
	if err := lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	capture := lease.capture.(*linuxCapture)
	entered, release := make(chan struct{}), make(chan struct{})
	previous := sendNetlinkRaw
	sendNetlinkRaw = func(session anchorSession, request []byte) error {
		close(entered)
		<-release
		report := queueReportRow(capture.queue, capture.outPort+1, 3)
		if err := os.WriteFile(namespaceQueueReportPath, []byte(report), 0o600); err != nil {
			return err
		}
		reply, err := fakeQueueAbsenceReply(request, session.boundPort())
		if err != nil {
			return err
		}
		binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.EPERM))
		session.(*fakeAnchorSession).setRawReply(reply, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		return nil
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		_ = lease.WaitClosed()
		sendNetlinkRaw = previous
	})
	closed := make(chan error, 1)
	start := time.Now()
	go func() { closed <- lease.Close(nil) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("did not reach actual release scan")
	}
	if err := waitWithin(t, "bounded Lease.Close", closed); !errors.Is(err, ErrLeaseCloseIncomplete) {
		t.Fatalf("pending release scan Close=%v, want incomplete", err)
	}
	if elapsed := time.Since(start); elapsed > 2*leaseCloseGrace || elapsed < leaseCloseGrace {
		t.Fatalf("caller bound elapsed=%s, grace=%s", elapsed, leaseCloseGrace)
	}
	if capture.retired.Load() || engine.ActiveLeases() != 1 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 1 || data.closings() != 1 {
		t.Fatal("pending receipt lost retained owner/metadata/charge")
	}
	select {
	case <-lease.closeDone:
		t.Fatal("teardown finished without the release observation")
	default:
	}
	close(release)
	released = true
	if err := lease.WaitClosed(); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if !capture.retired.Load() || engine.ActiveLeases() != 0 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 0 || data.closings() != 1 {
		t.Fatal("fresh replacement receipt did not finish the original teardown")
	}
}
