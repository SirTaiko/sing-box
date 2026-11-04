//go:build linux

package desync

import (
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

// These finite ordinary-success models use only the existing per-capture
// transport interface. They open no socket, retire no capture and never model
// unread data: pending is always false. RW-M5 is deliberately NOT_RUN.
type receiveWake41Transport struct {
	t            *testing.T
	capture      *linuxCapture
	receive      func() ([]netlink.Message, error)
	deadline     func(time.Time) error
	send         func(netlink.Message) (netlink.Message, error)
	mu           sync.Mutex
	events       []string
	pendingCalls int
}

func (q *receiveWake41Transport) event(s string) {
	q.mu.Lock()
	q.events = append(q.events, s)
	q.mu.Unlock()
}
func (q *receiveWake41Transport) snapshot() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.events...)
}
func (q *receiveWake41Transport) Receive() ([]netlink.Message, error) { return q.receive() }
func (q *receiveWake41Transport) SetReadDeadline(d time.Time) error {
	if !d.IsZero() && d.After(time.Now()) {
		q.t.Error("efficiency invariant: stop/rearm requested a future interval")
	}
	return q.deadline(d)
}
func (q *receiveWake41Transport) Send(m netlink.Message) (netlink.Message, error) {
	return q.send(m)
}
func (q *receiveWake41Transport) pending() (bool, error) {
	select {
	case <-q.capture.done:
	default:
		q.t.Error("pending before actual receive-loop join")
	}
	q.pendingCalls++ // sole stopReceive caller; inspected after its completion
	q.event("pending-false")
	return false, nil
}
func (*receiveWake41Transport) Execute(netlink.Message) ([]netlink.Message, error) {
	panic("receive wake model must not execute CONFIG or retirement")
}
func (*receiveWake41Transport) Close() error      { panic("ordinary wake must not close transport") }
func (*receiveWake41Transport) boundPort() uint32 { return 41 }

func receiveWake41Capture(t *testing.T) (*linuxCapture, *receiveWake41Transport) {
	t.Helper()
	// A valid inbound UDP packet takes the ordinary immediate pass path: no
	// outbound flow, hold, injector, native owner, endpoint or retirement state.
	l := &Lease{engine: &Engine{config: &Config{}}, intent: Intent{Family: FamilyIPv4}}
	c := &linuxCapture{lease: l, queue: 12000, inQueue: 12001, started: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	q := &receiveWake41Transport{t: t, capture: c}
	c.nl = q
	return c, q
}
func receiveWake41Wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second): // hung-test guard, never a latency oracle
		t.Fatal("receive wake model barrier did not complete")
	}
}
func receiveWake41Stop(t *testing.T, c *linuxCapture) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := c.stopReceive(); err != nil {
			t.Errorf("ordinary stopReceive: %v", err)
		}
	}()
	return done
}
func receiveWake41Check(t *testing.T, c *linuxCapture, q *receiveWake41Transport, want []string) {
	t.Helper()
	receiveWake41Wait(t, c.done)
	if got := q.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
	if q.pendingCalls != 1 || c.lease.failed != nil || c.retired.Load() {
		t.Fatal("expected one false pending observation, no failure and no retirement receipt")
	}
}
func receiveWake41Messages(t *testing.T, count int) []netlink.Message {
	t.Helper()
	if count < 1 || count > 2 {
		t.Fatal("success model permits at most two records")
	}
	frame := make([]byte, 28)
	frame[0], frame[8], frame[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	copy(frame[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	binary.BigEndian.PutUint16(frame[20:22], 443)
	binary.BigEndian.PutUint16(frame[22:24], 12345)
	binary.BigEndian.PutUint16(frame[24:26], 8)
	if _, err := ParsePacket(frame); err != nil {
		t.Fatal(err)
	}
	var messages []netlink.Message
	for i := 1; i <= count; i++ {
		id := make([]byte, 4)
		binary.BigEndian.PutUint32(id, uint32(i))
		attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: nfqPacketID, Data: id}, {Type: nfqPacketPayload, Data: frame}})
		if err != nil {
			t.Fatal(err)
		}
		messages = append(messages, netlink.Message{Header: netlink.Header{Type: 3 << 8}, Data: append([]byte{2, 0, 0x2e, 0xe1}, attrs...)})
	}
	return messages
}
func receiveWake41Send(q *receiveWake41Transport, m netlink.Message) uint32 {
	q.t.Helper()
	attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
	if err != nil || len(attrs) != 1 || len(attrs[0].Data) != 8 {
		q.t.Error("unexpected ordinary verdict encoding", err)
		return 0
	}
	if binary.BigEndian.Uint16(m.Data[2:4]) != 12001 || binary.BigEndian.Uint32(attrs[0].Data[:4]) != nfqueueVerdictAccept {
		q.t.Error("ordinary inbound record did not pass unchanged")
	}
	return binary.BigEndian.Uint32(attrs[0].Data[4:])
}

func TestSource41ReceiveWakeDefaults(t *testing.T) { // RW-M0: two cases, first runtime selector
	t.Run("nil", func(t *testing.T) {
		if err := new(linuxCapture).stopReceive(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unstarted", func(t *testing.T) {
		c, q := receiveWake41Capture(t)
		c.started = false
		if err := c.stopReceive(); err != nil {
			t.Fatal(err)
		}
		if c.stopping.Load() || len(q.snapshot()) != 0 || q.pendingCalls != 0 {
			t.Fatal("unstarted lane was touched")
		}
	})
}

func TestSource41ReceiveWakeIdle(t *testing.T) { // RW-M1
	c, q := receiveWake41Capture(t)
	entered, expired := make(chan struct{}), make(chan struct{})
	q.receive = func() ([]netlink.Message, error) {
		q.event("read")
		close(entered)
		<-expired
		q.event("expired")
		return nil, os.ErrDeadlineExceeded // intentional ordinary read interruption only
	}
	q.deadline = func(d time.Time) error {
		if d.IsZero() {
			q.event("clear")
			return nil
		}
		if !c.stopping.Load() {
			t.Error("stop not published before setter")
		}
		q.event("stop")
		close(expired)
		return nil
	}
	go c.loop()
	receiveWake41Wait(t, entered)
	receiveWake41Wait(t, receiveWake41Stop(t, c))
	receiveWake41Check(t, c, q, []string{"read", "stop", "expired", "pending-false", "clear"})
}

func TestSource41ReceiveWakeBatchSetterOrder(t *testing.T) { // RW-M2/M3; successful synchronous Send callbacks, not semantic Hold
	for _, rearmFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("rearm-first-", rearmFirst), func(t *testing.T) {
			c, q := receiveWake41Capture(t)
			messages := receiveWake41Messages(t, 2)
			firstSend, releaseSend := make(chan struct{}), make(chan struct{})
			stopEntered, releaseStop, rearmed := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var reads, setters atomic.Int32
			q.receive = func() ([]netlink.Message, error) {
				if reads.Add(1) == 1 {
					q.event("batch")
					return messages, nil
				}
				q.event("next-read")
				return nil, os.ErrDeadlineExceeded
			}
			q.send = func(m netlink.Message) (netlink.Message, error) {
				id := receiveWake41Send(q, m)
				q.event(fmt.Sprint("send-enter-", id))
				if id == 1 {
					close(firstSend)
					<-releaseSend
				}
				q.event(fmt.Sprint("send-done-", id))
				return m, nil
			}
			q.deadline = func(d time.Time) error {
				if d.IsZero() {
					q.event("clear")
					return nil
				}
				if setters.Add(1) == 1 {
					q.event("stop-enter")
					if rearmFirst {
						close(stopEntered)
						<-releaseStop
					}
					q.event("stop-applied")
					if !rearmFirst {
						close(stopEntered)
					}
				} else {
					q.event("rearm")
					close(rearmed)
				}
				return nil
			}
			go c.loop()
			receiveWake41Wait(t, firstSend)
			stopped := receiveWake41Stop(t, c)
			receiveWake41Wait(t, stopEntered)
			select {
			case <-c.done:
				t.Fatal("loop ended while successful batch was active")
			default:
			}
			if q.pendingCalls != 0 {
				t.Fatal("stopper passed active batch")
			}
			close(releaseSend)
			if rearmFirst {
				receiveWake41Wait(t, rearmed)
				receiveWake41Wait(t, c.done)
				close(releaseStop)
			}
			receiveWake41Wait(t, stopped)
			want := []string{"batch", "send-enter-1", "stop-enter"}
			if !rearmFirst {
				want = append(want, "stop-applied")
			}
			want = append(want, "send-done-1", "send-enter-2", "send-done-2", "rearm", "next-read")
			if rearmFirst {
				want = append(want, "stop-applied")
			}
			want = append(want, "pending-false", "clear")
			receiveWake41Check(t, c, q, want)
		})
	}
}

func TestSource41ReceiveWakeNextRead(t *testing.T) { // RW-M4: stop after normal batch / false stopping check
	c, q := receiveWake41Capture(t)
	messages := receiveWake41Messages(t, 1)
	entered, expired := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	q.receive = func() ([]netlink.Message, error) {
		if reads.Add(1) == 1 {
			q.event("batch")
			return messages, nil
		}
		q.event("next-read")
		close(entered)
		<-expired
		return nil, os.ErrDeadlineExceeded
	}
	q.send = func(m netlink.Message) (netlink.Message, error) {
		q.event(fmt.Sprint("send-", receiveWake41Send(q, m)))
		return m, nil
	}
	q.deadline = func(d time.Time) error {
		if d.IsZero() {
			q.event("clear")
		} else {
			q.event("stop")
			close(expired)
		}
		return nil
	}
	go c.loop()
	receiveWake41Wait(t, entered)
	if got := q.snapshot(); !reflect.DeepEqual(got, []string{"batch", "send-1", "next-read"}) {
		t.Fatal("normal batch unexpectedly set a deadline", got)
	}
	receiveWake41Wait(t, receiveWake41Stop(t, c))
	receiveWake41Check(t, c, q, []string{"batch", "send-1", "next-read", "stop", "pending-false", "clear"})
}

func TestSource41ReceiveWakeReturnedBatch(t *testing.T) { // RW-M6: successful read already won, before interruption is observed
	c, q := receiveWake41Capture(t)
	messages := receiveWake41Messages(t, 2)
	entered, releaseRead, armed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var reads, setters atomic.Int32
	q.receive = func() ([]netlink.Message, error) {
		if reads.Add(1) == 1 {
			q.event("read")
			close(entered)
			<-releaseRead
			q.event("returned-batch")
			return messages, nil
		}
		q.event("next-read")
		return nil, os.ErrDeadlineExceeded
	}
	q.send = func(m netlink.Message) (netlink.Message, error) {
		q.event(fmt.Sprint("send-", receiveWake41Send(q, m)))
		return m, nil
	}
	q.deadline = func(d time.Time) error {
		if d.IsZero() {
			q.event("clear")
			return nil
		}
		if setters.Add(1) == 1 {
			q.event("stop")
			close(armed)
		} else {
			q.event("rearm")
		}
		return nil
	}
	go c.loop()
	receiveWake41Wait(t, entered)
	stopped := receiveWake41Stop(t, c)
	receiveWake41Wait(t, armed)
	close(releaseRead)
	receiveWake41Wait(t, stopped)
	receiveWake41Check(t, c, q, []string{"read", "stop", "returned-batch", "send-1", "send-2", "rearm", "next-read", "pending-false", "clear"})
}
