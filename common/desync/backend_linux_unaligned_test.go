//go:build linux

package desync

// Permanent regression for the native 31-byte NFQUEUE packet path
// (S26-NFQUEUE-UNALIGNED-PACKET). A real kernel datagram carries nlmsg_len=127
// on a 127-byte receive (strace-derived fixture), which the pinned
// netlink.Message.UnmarshalBinary rejects when handed that unaligned-length
// slice. These are model tests: the pinned socket.Conn and the production
// nfqueueSocketAdapter are the real composed objects, the descriptor underneath
// is an unprivileged AF_UNIX datagram socket pair, so no netfilter object is
// created and no host networking is used.
//
// The behavioural RED control is the exact submission26 production file: the
// authentic-fixture and residue cases fail there with "input data is not
// properly aligned for netlink message" while the negatives pass for a
// different reason, so a green run is not vacuous.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

// nativeUnalignedFixtureSHA256 is the independently verified identity of the
// strace-extracted native127 datagram (line 5349 of lab/linux/short31-raw
// .strace in the QA artifact). It is raw kernel bytes, not synthesized packet
// data.
const nativeUnalignedFixtureSHA256 = "c74df4dda2b7656c448dac8d8d7dd1b5fb34425efd1264f4e8b31daeb2204be7"

// newAdapterDatagramPair builds one pinned socket.Conn over an unprivileged
// AF_UNIX datagram pair and returns the production adapter around it plus the
// peer descriptor the model kernel writes datagrams to. Datagram framing is
// preserved, exactly like the netlink socket the production adapter owns.
func newAdapterDatagramPair(t *testing.T) (*nfqueueSocketAdapter, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	conn, err := socket.New(fds[0], "desync-unaligned-receive-test")
	if err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatalf("wrap pinned socket.Conn: %v", err)
	}
	adapter := &nfqueueSocketAdapter{conn: conn}
	t.Cleanup(func() {
		_ = adapter.Close()
		_ = unix.Close(fds[1])
	})
	return adapter, fds[1]
}

// nativeQueueDatagram builds one NFQNL_MSG_PACKET datagram with the given
// declared nlmsg_len. The exact length may be unaligned; the caller decides
// whether to append kernel alignment padding.
func nativeQueueDatagram(length int, fill byte) []byte {
	datagram := make([]byte, length)
	binary.NativeEndian.PutUint32(datagram[0:], uint32(length))
	binary.NativeEndian.PutUint16(datagram[4:], uint16(3<<8))
	binary.NativeEndian.PutUint32(datagram[8:], 0x11223344)
	binary.NativeEndian.PutUint32(datagram[12:], 0x55667788)
	for index := 16; index < length; index++ {
		datagram[index] = fill + byte(index)
	}
	return datagram
}

// padNativeDatagram appends the kernel alignment padding of one datagram.
func padNativeDatagram(datagram []byte) []byte {
	aligned := (len(datagram) + 3) &^ 3
	return append(datagram, make([]byte, aligned-len(datagram))...)
}

func sendDatagram(t *testing.T, peer int, datagram []byte) {
	t.Helper()
	if _, err := unix.Write(peer, datagram); err != nil {
		t.Fatalf("model kernel write: %v", err)
	}
}

// TestNFQueueAdapterReceiveNativeUnalignedDatagram is the authentic bytes plus
// every modulo-four residue through the actual owning adapter Receive.
func TestNFQueueAdapterReceiveNativeUnalignedDatagram(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "native-nfq-packet127.bin"))
	if err != nil {
		t.Fatalf("read authentic native fixture: %v", err)
	}
	if len(fixture) != 127 || binary.NativeEndian.Uint32(fixture) != 127 {
		t.Fatalf("authentic fixture length=%d declared=%d, want 127/127", len(fixture), binary.NativeEndian.Uint32(fixture))
	}
	sum := sha256.Sum256(fixture)
	if got := hex.EncodeToString(sum[:]); got != nativeUnalignedFixtureSHA256 {
		t.Fatalf("authentic fixture sha256=%s, want %s", got, nativeUnalignedFixtureSHA256)
	}

	// The untouched slice is the exact shape that failed natively: the pinned
	// decoder refuses the storage before reading the header. This is a
	// consumer control, not a production expectation.
	var pinned netlink.Message
	if err := pinned.UnmarshalBinary(fixture); err == nil || !strings.Contains(err.Error(), "aligned") {
		t.Fatalf("pinned decoder control error=%v, want the unaligned-storage rejection", err)
	}

	t.Run("authentic-native127", func(t *testing.T) {
		adapter, peer := newAdapterDatagramPair(t)
		sendDatagram(t, peer, fixture)
		messages, err := adapter.Receive()
		if err != nil {
			t.Fatalf("valid native 127B NFQUEUE datagram rejected: %v", err)
		}
		if len(messages) != 1 {
			t.Fatalf("messages=%d, want 1", len(messages))
		}
		message := messages[0]
		if message.Header.Length != 127 || uint16(message.Header.Type) != 0x300 {
			t.Fatalf("header length=%d type=%#x, want 127/0x300", message.Header.Length, uint16(message.Header.Type))
		}
		if len(message.Data) != 111 || !bytes.Equal(message.Data, fixture[16:127]) {
			t.Fatalf("payload length=%d equal=%v, want the declared 111 native bytes", len(message.Data), bytes.Equal(message.Data, fixture[16:]))
		}
		if message.Header.Sequence != binary.NativeEndian.Uint32(fixture[8:]) ||
			message.Header.PID != binary.NativeEndian.Uint32(fixture[12:]) {
			t.Fatalf("header identity changed: seq=%#x pid=%#x", message.Header.Sequence, message.Header.PID)
		}
		// The last NFQA attribute of the real datagram ends exactly at the
		// declared length without alignment padding. The pinned attribute
		// decoder must accept that exact byte sequence, because that is the
		// layer the capture loop parses after Receive.
		attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
		if err != nil {
			t.Fatalf("native attribute area rejected: %v", err)
		}
		var packetID, payload []byte
		for _, attribute := range attributes {
			switch attribute.Type & 0x3fff {
			case nfqPacketID:
				packetID = attribute.Data
			case nfqPacketPayload:
				payload = attribute.Data
			}
		}
		if len(packetID) != 7 || binary.BigEndian.Uint32(packetID) != 1 || len(payload) != 83 {
			t.Fatalf("native attributes id=%d payload=%d, want the 7-byte packet header for id 1 with 83 payload bytes", len(packetID), len(payload))
		}
	})

	// Every modulo-four declared length: 16,17,18,19,20 cover residues 0..3
	// and the empty-payload boundary; 127 is the observed native packet.
	t.Run("final-length-residues", func(t *testing.T) {
		for _, length := range []int{16, 17, 18, 19, 20, 127} {
			adapter, peer := newAdapterDatagramPair(t)
			datagram := nativeQueueDatagram(length, byte(length))
			sendDatagram(t, peer, datagram)
			messages, err := adapter.Receive()
			if err != nil {
				t.Fatalf("length=%d: %v", length, err)
			}
			if len(messages) != 1 || messages[0].Header.Length != uint32(length) ||
				!bytes.Equal(messages[0].Data, datagram[16:]) {
				t.Fatalf("length=%d: messages=%d header=%d data_equal=%v", length, len(messages),
					messages[0].Header.Length, bytes.Equal(messages[0].Data, datagram[16:]))
			}
		}
	})

	// The same declared lengths with complete kernel alignment padding: the
	// padding belongs to the transport, never to the declared payload.
	t.Run("padded-length-residues", func(t *testing.T) {
		for _, length := range []int{16, 17, 18, 19, 20, 127} {
			adapter, peer := newAdapterDatagramPair(t)
			datagram := nativeQueueDatagram(length, byte(length))
			padded := padNativeDatagram(datagram)
			sendDatagram(t, peer, padded)
			messages, err := adapter.Receive()
			if err != nil {
				t.Fatalf("padded length=%d: %v", length, err)
			}
			if len(messages) != 1 || messages[0].Header.Length != uint32(length) ||
				!bytes.Equal(messages[0].Data, datagram[16:]) {
				t.Fatalf("padded length=%d: messages=%d header=%d data_equal=%v", length, len(messages),
					messages[0].Header.Length, bytes.Equal(messages[0].Data, datagram[16:]))
			}
		}
	})

	t.Run("multi-message-partition", func(t *testing.T) {
		lengths := []int{127, 20, 18, 16}
		var datagram []byte
		expected := make([][]byte, 0, len(lengths))
		for index, length := range lengths {
			message := nativeQueueDatagram(length, byte(0x40+index))
			expected = append(expected, message[16:])
			if index == len(lengths)-1 {
				// The final message ends the datagram without padding.
				datagram = append(datagram, message...)
				continue
			}
			datagram = append(datagram, padNativeDatagram(message)...)
		}
		adapter, peer := newAdapterDatagramPair(t)
		sendDatagram(t, peer, datagram)
		messages, err := adapter.Receive()
		if err != nil {
			t.Fatalf("partitioned datagram: %v", err)
		}
		if len(messages) != len(lengths) {
			t.Fatalf("messages=%d, want %d", len(messages), len(lengths))
		}
		for index, message := range messages {
			if message.Header.Length != uint32(lengths[index]) || !bytes.Equal(message.Data, expected[index]) {
				t.Fatalf("message %d length=%d data_equal=%v", index, message.Header.Length,
					bytes.Equal(message.Data, expected[index]))
			}
		}
	})

	t.Run("negative-datagrams", func(t *testing.T) {
		cases := []struct {
			name     string
			datagram []byte
			want     string
		}{
			{"declared-longer-than-datagram", nativeQueueDatagram(128, 1)[:127], "malformed netlink datagram"},
			{"declared-below-header", nativeQueueDatagram(16, 2), "malformed netlink datagram"},
			{"trailing-junk", append(nativeQueueDatagram(20, 3), 0xde, 0xad, 0xbe), "trailing bytes"},
			{"partial-padding", append(nativeQueueDatagram(18, 4), 0x00), "incomplete padding"},
			{"length-overflow", func() []byte {
				datagram := nativeQueueDatagram(16, 5)
				binary.NativeEndian.PutUint32(datagram, ^uint32(0))
				return datagram
			}(), "malformed netlink datagram"},
			{"empty-datagram", nil, "empty netlink datagram"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				adapter, peer := newAdapterDatagramPair(t)
				if testCase.name == "declared-below-header" {
					binary.NativeEndian.PutUint32(testCase.datagram, 15)
				}
				sendDatagram(t, peer, testCase.datagram)
				messages, err := adapter.Receive()
				if err == nil {
					t.Fatalf("accepted negative datagram with %d messages", len(messages))
				}
				if !strings.Contains(err.Error(), testCase.want) {
					t.Fatalf("error=%v, want substring %q", err, testCase.want)
				}
			})
		}
	})
}
