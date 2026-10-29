//go:build linux

package desync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise inject itself, not a reconstructed sockaddr helper. All namespace
// and raw syscalls use the existing bounded injectionModel; no real setns or
// raw socket is performed. Transport ports belong to the unchanged IP packet.
func TestLinuxInjectionRawSockaddr(t *testing.T) {
	for _, tc := range []struct {
		name      string
		family    Family
		tcp       bool
		linkLocal bool
		port      uint16
	}{
		{"ipv6/udp", FamilyIPv6, false, false, 30000},
		{"ipv6/udp-max-port", FamilyIPv6, false, false, 65535},
		{"ipv6/tcp", FamilyIPv6, true, false, 443},
		{"ipv6/tcp-max-port", FamilyIPv6, true, false, 65535},
		{"ipv6/link-local-udp", FamilyIPv6, false, true, 30000},
		{"ipv4/udp-control", FamilyIPv4, false, false, 30000},
		{"ipv4/tcp-control", FamilyIPv4, true, false, 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, raw := injectionFixture(t, tc.family)
			if tc.tcp {
				build := buildIPv4TCP
				if tc.family == FamilyIPv6 {
					build = buildIPv6TCP
				}
				raw = build(t, []byte{0, 1, 2, 0xff}, 0x31415926, 0x18).Raw
			}
			if tc.linkLocal {
				src := netip.MustParseAddr("fe80::10").As16()
				dst := netip.MustParseAddr("fe80::20").As16()
				copy(raw[8:24], src[:])
				copy(raw[24:40], dst[:])
				// An IP packet carries no zone ID. Preserve the existing zero
				// sockaddr scope and SO_BINDTODEVICE (checked by the model),
				// rather than inventing an interface index in this port fix.
			}
			parsed, err := ParsePacket(raw)
			if err != nil {
				t.Fatal(err)
			}
			binary.BigEndian.PutUint16(raw[parsed.IPHeaderLen+2:], tc.port)
			if err = refreshChecksums(raw, parsed); err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), raw...)
			m := installInjectionModel(t, c, raw)
			send := sendInjectionPacket
			sends := 0
			sendInjectionPacket = func(fd int, packet []byte, flags int, destination unix.Sockaddr) error {
				sends++
				if !bytes.Equal(packet, before) {
					t.Error("raw send changed full IP/transport packet bytes")
				}
				if port := binary.BigEndian.Uint16(packet[parsed.IPHeaderLen+2:]); port != tc.port {
					t.Errorf("transport destination port=%d, want %d", port, tc.port)
				}
				return send(fd, packet, flags, destination)
			}
			if err = c.inject(raw); err != nil {
				t.Fatal(err)
			}
			if sends != 1 || !bytes.Equal(raw, before) || !c.lease.lowHopSent.Load() {
				t.Errorf("send count=%d, packet unchanged=%t, injection recorded=%t", sends, bytes.Equal(raw, before), c.lease.lowHopSent.Load())
			}
			m.assertEvents(injectionSuccessEvents(tc.family))
		})
	}
}

// Port construction must not change the existing error/lifetime policy: sends
// are not retried, Close is attempted once before restore, and its error remains
// ignored while send and restoration errors retain their identities.
func TestLinuxInjectionRawSockaddrErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		send    bool
		restore bool
	}{
		{"close", false, false},
		{"send-close", true, false},
		{"restore-close", false, true},
		{"send-restore-close", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, raw := injectionFixture(t, FamilyIPv6)
			before := append([]byte(nil), raw...)
			m := installInjectionModel(t, c, raw)
			if tc.send {
				m.fail = "send"
			}
			if tc.restore {
				m.restoreErr = unix.EPERM
			}
			closeFD := closeInjectionSocket
			closes := 0
			closeInjectionSocket = func(fd int) error {
				closes++
				if err := closeFD(fd); err != nil {
					t.Error(err)
				}
				return unix.EINTR
			}
			err := c.inject(raw)
			if errors.Is(err, errInjectionModel) != tc.send || errors.Is(err, unix.EPERM) != tc.restore || errors.Is(err, unix.EINTR) {
				t.Errorf("send/restore identity or ignored Close semantics changed: %v", err)
			}
			if !tc.send && !tc.restore && err != nil {
				t.Errorf("Close error became fatal: %v", err)
			}
			if closes != 1 || !bytes.Equal(raw, before) || c.lease.lowHopSent.Load() == tc.send {
				t.Errorf("close count=%d, packet unchanged=%t, injection recorded=%t", closes, bytes.Equal(raw, before), c.lease.lowHopSent.Load())
			}
			m.assertEvents(injectionSuccessEvents(FamilyIPv6))
		})
	}
}
