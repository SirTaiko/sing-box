//go:build linux

package desync

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Real Engine/Lease authenticated split-Initial replay into the real raw
// injection wrapper. Only namespace/raw syscalls are modelled; no kernel send
// or native namespace qualification is claimed.
func TestLinuxInjectionHeldFlowLockBoundary(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(strconv.Itoa(int(family)), func(t *testing.T) {
			fixture := newUDPPeerEngine(t, 4, "", "["+strings.ReplaceAll(qa519UDPRules("010203", 1, ""), "443", "23456")+"]")
			c, p := injectionFixture(t, family)
			parsed, err := ParsePacket(p)
			if err != nil {
				t.Fatal(err)
			}
			src := netip.AddrPortFrom(parsed.Src, parsed.SrcPort)
			dst := netip.AddrPortFrom(parsed.Dst, parsed.DstPort)
			lease, err := fixture.engine.NewAttempt(Intent{Family: family, Transport: TransportUDP, Source: src, Destination: dst})
			if err != nil {
				t.Fatal(err)
			}
			lease.SetLocalAddress(src)
			if err = lease.StartCapture(); err != nil {
				t.Fatal(err)
			}
			c.lease = lease
			lease.setSocketMark(0x123)
			lease.setSocketDevice("model-device")
			m := installInjectionModel(t, c, p)
			originalSend := sendInjectionPacket
			sends := 0
			sendInjectionPacket = func(fd int, b []byte, flags int, sa unix.Sockaddr) error {
				sends++
				lease.mu.Lock()
				flow := lease.udpFlows[flowKey(dst)]
				lease.mu.Unlock()
				if flow == nil {
					t.Error("no actual peer flow")
					return errInjectionModel
				}
				assertHeldIOLocksAvailable(t, lease, flow)
				return originalSend(fd, b, flags, sa)
			}
			inject := func(raw []byte) error {
				m.packet = append([]byte(nil), raw...)
				return c.inject(raw)
			}
			head, tail := qa519SplitInitials(t, "scope.example", 40, qa519DCID(0x19), 1, 1)
			completed := 0
			for _, data := range [][]byte{head, tail} {
				packet := udpPeerPacket(t, src, dst, data)
				if v := lease.HandlePacket(packet.Raw, DirectionOutbound, inject, func(Verdict, string, []byte) {
					lease.mu.Lock()
					flow := lease.udpFlows[flowKey(dst)]
					lease.mu.Unlock()
					assertHeldIOLocksAvailable(t, lease, flow)
					completed++
				}); v != VerdictHold {
					t.Fatalf("verdict %v, want held replay", v)
				}
			}
			if sends != 1 || completed != 2 {
				t.Fatalf("vacuous witness sends=%d completed=%d", sends, completed)
			}
			t.Logf("actual held replay reached raw Sendto seam %d time; originals completed %d", sends, completed)
		})
	}
}
