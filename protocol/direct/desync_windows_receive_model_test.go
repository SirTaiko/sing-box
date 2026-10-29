//go:build desync_windows_model && !windows

package direct

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/windivert"
	"github.com/sagernet/sing-box/option"
)

// The returned wrapper, producer, capture, Lease and QUIC replay are production
// code. Only the native socket/WinDivert boundary is modeled. A next Recv entry
// poisons the previous scratch: observing it proves that the reader relinquished
// that scratch after an immutable copy, not merely that a driver returned bytes.
type receiveModelConn struct {
	net.Conn
	write  func([]byte) (int, error)
	closed atomic.Int32
}

func (c *receiveModelConn) Write(p []byte) (int, error) { return c.write(p) }
func (c *receiveModelConn) Close() error                { c.closed.Add(1); return nil }

func receiveModelFrame(payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 10})
	copy(p[16:20], []byte{198, 51, 100, 7})
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}
func receiveModelFixture(t *testing.T, name string) []byte {
	t.Helper()
	p, e := os.ReadFile("testdata/windows-rx-" + name + ".hex")
	if e != nil {
		t.Fatal(e)
	}
	b, e := hex.DecodeString(strings.TrimSpace(string(p)))
	if e != nil || len(b) != 278 {
		t.Fatal("authenticated fixture", e, len(b))
	}
	return b
}
func receiveModelWait(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func TestWindowsReceiveProgressDuringSynchronousRelease(t *testing.T) {
	for _, pause := range []string{"complete", "inject", "timer"} {
		for _, ending := range []string{"no-close", "close", "cancel"} {
			t.Run(pause+"/"+ending, func(t *testing.T) {
				head, tail := receiveModelFixture(t, "head"), receiveModelFixture(t, "tail")
				third := []byte("QA593-precancel-O1")
				var opt option.DirectDesyncOptions
				if err := json.Unmarshal([]byte(`{"enabled":true,"limits":{"hold_timeout":"100ms","max_leases":1},"rules":[{"network":["udp"],"protocol":["quic"],"methods":["fake"],"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"ab"}]}}]}`), &opt); err != nil {
					t.Fatal(err)
				}
				cfg, err := desync.Compile(&opt, "")
				if err != nil {
					t.Fatal(err)
				}
				input := make(chan []byte, 8)
				stop := make(chan struct{})
				nativeDone := make(chan struct{})
				copiedThird := make(chan struct{})
				entered, release := make(chan struct{}), make(chan struct{})
				var enterOnce, releaseOnce, stopOnce, doneOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				var mu sync.Mutex
				var sent [][]byte
				var sendAddresses [][80]byte
				var receives int
				var previous []byte
				var previousThird bool
				h := &windivert.Handle{DoneChan: nativeDone}
				h.RecvFunc = func(buffer []byte) (int, windivert.Address, error) {
					for i := range previous {
						previous[i] = 0xdd
					}
					previous = nil
					if previousThird {
						close(copiedThird)
						previousThird = false
					}
					var packet []byte
					select {
					case packet = <-input:
					default:
						select {
						case packet = <-input:
						case <-stop:
							return 0, windivert.Address{}, windivert.ReplayDrained
						}
					}
					copy(buffer, packet)
					previous = buffer[:len(packet)]
					previousThird = bytes.Equal(packet, receiveModelFrame(third))
					receives++
					var address windivert.Address
					bits := (*[80]byte)(unsafe.Pointer(&address))
					for i := range bits {
						bits[i] = byte(i + receives)
					}
					address.SetOutbound(true)
					return len(packet), address, nil
				}
				h.SendFunc = func(p []byte, a *windivert.Address) (int, error) {
					original := bytes.Equal(p, receiveModelFrame(head))
					if (pause == "inject" && !original && len(p) > 28 && !bytes.Equal(p, receiveModelFrame(tail))) || (pause != "inject" && original) {
						enterOnce.Do(func() { close(entered); <-release })
					}
					mu.Lock()
					sent = append(sent, bytes.Clone(p))
					sendAddresses = append(sendAddresses, *(*[80]byte)(unsafe.Pointer(a)))
					mu.Unlock()
					return len(p), nil
				}
				h.ShutdownFunc = func() error { stopOnce.Do(func() { close(stop) }); return nil }
				h.CloseFunc = func() error { doneOnce.Do(func() { close(nativeDone) }); return nil }
				opens := 0
				windivert.ReplayOpen = func(*windivert.Filter, windivert.Layer, int16, windivert.Flag) (*windivert.Handle, error) {
					opens++
					if opens == 1 {
						return h, nil
					}
					d := make(chan struct{})
					s := make(chan struct{})
					var so, do sync.Once
					return &windivert.Handle{RecvFunc: func([]byte) (int, windivert.Address, error) {
						<-s
						return 0, windivert.Address{}, windivert.ReplayDrained
					}, SendFunc: func([]byte, *windivert.Address) (int, error) { panic("unexpected inbound send") }, ShutdownFunc: func() error { so.Do(func() { close(s) }); return nil }, CloseFunc: func() error { do.Do(func() { close(d) }); return nil }, DoneChan: d}, nil
				}
				defer func() { windivert.ReplayOpen = nil }()
				e, err := desync.NewEngine(cfg, desync.NewWindowsReplayBackend())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { unblock(); _ = e.Close() }()
				l, err := e.NewAttempt(desync.Intent{Family: desync.FamilyIPv4, Transport: desync.TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
				if err != nil {
					t.Fatal(err)
				}
				l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
				if err = l.StartCapture(); err != nil {
					t.Fatal(err)
				}
				raw := &receiveModelConn{write: func(p []byte) (int, error) { input <- receiveModelFrame(p); return len(p), nil }}
				owner := &desyncLease{lease: l, ctx: context.Background(), intent: dialer.AttemptIntent{Network: "udp"}}
				returned, err := owner.AttachConn(raw)
				if err != nil {
					t.Fatal(err)
				}
				write := func(p []byte) {
					t.Helper()
					n, e := returned.Write(p)
					if n != len(p) || e != nil {
						t.Fatalf("actual returned Write: n=%d error=%v", n, e)
					}
				}
				write(head)
				if pause != "timer" {
					write(tail)
				}
				receiveModelWait(t, entered, "synchronous original/generated Send was not entered")
				if !desync.WindowsModelLocksAvailable(l) {
					t.Fatal("callback holds Engine/Lease/flow lock")
				}
				// Intentionally synchronous BEFORE unblock: gate must not pressure-pause at
				// callback entry or fake a write result to make this regression succeed.
				write(third)
				receiveModelWait(t, copiedThird, "RP-PROGRESS: reader did not copy third returned Write before synchronous release unblock")
				wantBytes := int64(612)
				if pause == "timer" {
					wantBytes = 306
				}
				if got := desync.WindowsModelHeldBytes(e); got != wantBytes {
					t.Fatalf("semantic bytes=%d want %d (staging must be separate)", got, wantBytes)
				}
				if err = l.Err(); err != nil {
					t.Fatalf("in-budget fixture latched failure: %v", err)
				}
				mu.Lock()
				for _, p := range sent {
					if bytes.Equal(p, receiveModelFrame(third)) {
						t.Error("third original overtook held originals")
					}
				}
				mu.Unlock()
				done := make(chan error, 1)
				if ending == "close" {
					go func() { done <- l.Close(nil) }()
				} else if ending == "cancel" {
					ctx, cancel := context.WithCancel(context.Background())
					after := context.AfterFunc(ctx, func() { done <- l.Close(ctx.Err()) })
					defer after()
					cancel()
				}
				unblock()
				if ending == "no-close" { // Wait for the ordinary running worker, not a Close workaround.
					deadline := time.After(time.Second)
					for {
						mu.Lock()
						seen := false
						for _, p := range sent {
							seen = seen || bytes.Equal(p, receiveModelFrame(third))
						}
						mu.Unlock()
						if seen {
							break
						}
						select {
						case <-deadline:
							t.Fatal("running worker failed to deliver third")
						case <-time.After(time.Millisecond):
						}
					}
					done <- l.Close(nil)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				if err = l.WaitClosed(); err != nil {
					t.Fatal(err)
				}
				if err = l.WaitCaptureRetired(); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				defer mu.Unlock()
				originals := [][]byte{receiveModelFrame(head)}
				fakes := 10
				if pause == "timer" {
					fakes = 0
				} else {
					originals = append(originals, receiveModelFrame(tail))
				}
				originals = append(originals, receiveModelFrame(third))
				if len(sent) != fakes+len(originals) {
					t.Fatalf("sends=%d fake=%d originals=%d", len(sent), fakes, len(originals))
				}
				for i, p := range originals {
					at := fakes + i
					if !bytes.Equal(sent[at], p) {
						t.Errorf("original %d corrupted/reordered", i)
					}
					var a windivert.Address
					b := (*[80]byte)(unsafe.Pointer(&a))
					for j := range b {
						b[j] = byte(j + i + 1)
					}
					a.SetOutbound(true)
					if sendAddresses[at] != *b {
						t.Errorf("original %d full80 address corrupted", i)
					}
				}
				if desync.WindowsModelHeldBytes(e) != 0 || e.ActiveLeases() != 0 {
					t.Fatal("joined owners still charged")
				}
				if err = returned.Close(); err != nil && !errors.Is(err, desync.ErrLeaseCloseIncomplete) {
					t.Fatal(err)
				}
				if raw.closed.Load() != 1 {
					t.Fatal("endpoint not closed exactly once")
				}
			})
		}
	}
}
