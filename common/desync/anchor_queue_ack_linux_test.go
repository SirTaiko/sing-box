//go:build linux

package desync

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// Offline ACK bytes -> production classifier -> pinned netlink.Conn.Execute ->
// production bindQueueOn. nltest.Dial constructs an in-memory Socket, NOT a dial.
func TestSource37ConfigRejectionProvenance(t *testing.T) {
	for _, kind := range []string{"negative", "ack0", "wrong-sequence", "wrong-port", "wrong-echo", "wrong-peer", "multicast", "truncated-echo", "capped", "tlvs", "positive-code", "errno-out-of-range", "syscall", "timeout", "raw-operror"} {
		t.Run(kind, func(t *testing.T) {
			var saw bool
			conn := nltest.Dial(func(reqs []netlink.Message) ([]netlink.Message, error) {
				if len(reqs) != 1 {
					t.Fatal("MODEL: request missing")
				}
				req := reqs[0]
				saw = true
				if kind == "syscall" {
					return nil, os.NewSyscallError("recvfrom", unix.EPERM)
				}
				if kind == "timeout" {
					return nil, os.ErrDeadlineExceeded
				}
				if kind == "raw-operror" {
					return nil, &netlink.OpError{Op: "receive", Err: unix.EPERM, Sequence: req.Header.Sequence}
				}
				raw, err := req.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				code := -int32(unix.EPERM)
				if kind == "ack0" {
					code = 0
				}
				if kind == "positive-code" {
					code = 1
				}
				if kind == "errno-out-of-range" {
					code = -4096
				}
				reply := netlink.Message{Header: netlink.Header{Type: netlink.Error, Sequence: req.Header.Sequence, PID: req.Header.PID}, Data: binary.NativeEndian.AppendUint32(nil, uint32(code))}
				reply.Data = append(reply.Data, raw...)
				peer := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
				switch kind {
				case "wrong-sequence":
					reply.Header.Sequence++
				case "wrong-port":
					reply.Header.PID++
				case "wrong-echo":
					reply.Data[len(reply.Data)-1] ^= 1
				case "wrong-peer":
					peer.Pid = 77
				case "multicast":
					peer.Groups = 1
				case "truncated-echo":
					reply.Data = reply.Data[:len(reply.Data)-4]
				case "capped":
					reply.Header.Flags = netlink.Capped
				case "tlvs":
					reply.Header.Flags = netlink.AcknowledgeTLVs
				}
				reply.Header.Length = uint32(16 + len(reply.Data))
				wire, err := reply.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := parseNetlinkDatagram(wire)
				if err != nil {
					t.Fatal(err)
				}
				if known := matchingQueueConfigRejection(decoded, peer, raw); known != nil {
					return nil, known
				}
				return decoded, nil
			})
			defer conn.Close()
			c := &linuxCapture{}
			transport := netlinkQueueConn{Conn: conn, port: nltest.PID}
			err := c.bindQueueOn(0, FamilyIPv4, transport)
			if !saw {
				t.Fatal("MODEL: actual caller not reached")
			}
			if kind == "ack0" {
				if err != nil || c.queueBindings[0] != queueBindingBound {
					t.Fatalf("MODEL ACK0 lost: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("MODEL: failed BIND reported success")
			}
			want := queueBindingUncertain
			if kind == "negative" {
				want = queueBindingUnbound
				if !errors.Is(err, unix.EPERM) {
					t.Fatal("errno lost")
				}
			}
			if c.queueBindings[0] != want {
				t.Fatalf("MODEL: %s effect=%v want=%v", kind, c.queueBindings[0], want)
			}
		})
	}
}
