//go:build linux

package desync

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Ordinary success MODEL only: existing in-memory NFT/queue transports, regular
// file namespace identity, no native sockets/setns/fork or injected failures.
// Counts are generations, not reused numerical FDs or a performance oracle.
type metadataOpen42Ledger struct {
	mu                                                  sync.Mutex
	t                                                   *testing.T
	opening                                             bool
	tx, live, opens, closes, txOpens, txCloses, configs int
	dumps, generations, batches                         int
	familyGenerations                                   map[byte]int
	events                                              []string
}

func (l *metadataOpen42Ledger) event(s string) { l.events = append(l.events, s) }

type metadataOpen42Session struct {
	*fakeAnchorSession
	ledger *metadataOpen42Ledger
	closed bool
}

func (s *metadataOpen42Session) check() {
	if s.closed || s.ledger.tx != 1 || s.ledger.live != 1 {
		s.ledger.t.Error("metadata use outside its live transaction")
	}
}
func (s *metadataOpen42Session) batch(rs []nftRequest) ([]nftReply, error) {
	l := s.ledger
	l.mu.Lock()
	s.check()
	l.batches++
	l.event("batch")
	l.mu.Unlock()
	return s.fakeAnchorSession.batch(rs)
}
func (s *metadataOpen42Session) dump(typ uint16, f byte, as []netlink.Attribute) ([]nftReply, error) {
	l := s.ledger
	l.mu.Lock()
	s.check()
	l.dumps++
	l.event("dump")
	l.mu.Unlock()
	return s.fakeAnchorSession.dump(typ, f, as)
}
func (s *metadataOpen42Session) generation(f byte) (uint32, error) {
	l := s.ledger
	l.mu.Lock()
	s.check()
	l.generations++
	l.familyGenerations[f]++
	l.event("generation")
	l.mu.Unlock()
	return s.fakeAnchorSession.generation(f)
}
func (s *metadataOpen42Session) Close() error {
	l := s.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	s.check()
	s.closed = true
	l.live--
	l.closes++
	l.event("metadata-close")
	return s.fakeAnchorSession.Close()
}

type metadataOpen42Queue struct {
	nfqueueTransport
	ledger      *metadataOpen42Ledger
	receiveOnce sync.Once
}

func (q *metadataOpen42Queue) Execute(m netlink.Message) ([]netlink.Message, error) {
	l := q.ledger
	l.mu.Lock()
	if l.opening {
		if l.tx != 1 || l.live != 1 {
			l.t.Error("opening CONFIG outside the publication metadata transaction")
		}
		l.configs++
		l.event("config")
	}
	l.mu.Unlock()
	return q.nfqueueTransport.Execute(m)
}
func (q *metadataOpen42Queue) Receive() ([]netlink.Message, error) {
	q.receiveOnce.Do(func() {
		l := q.ledger
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.live != 0 || l.tx != 0 {
			l.t.Error("receive loop started before metadata/transaction Close")
		}
	})
	return q.nfqueueTransport.Receive()
}

func metadataOpen42Observe(t *testing.T, seams *linuxCaptureSeams) *metadataOpen42Ledger {
	t.Helper()
	l := &metadataOpen42Ledger{t: t, familyGenerations: make(map[byte]int)}
	bind, closeFD, openSession, openQueue := bindAnchorTransactionSocket, closeAnchorTransactionSocket, openAnchorSession, openQueueTransport
	bindAnchorTransactionSocket = func(name string) (int, error) {
		fd, err := bind(name)
		if err != nil {
			return fd, err
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.tx++
		l.txOpens++
		l.event("tx-open")
		return fd, nil
	}
	closeAnchorTransactionSocket = func(fd int) error {
		l.mu.Lock()
		if l.live != 0 {
			t.Error("transaction Close before metadata Close")
		}
		l.tx--
		l.txCloses++
		l.event("tx-close")
		l.mu.Unlock()
		return closeFD(fd)
	}
	openAnchorSession = func() (anchorSession, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.tx != 1 || l.live != 0 {
			t.Error("metadata open without exclusive transaction")
		}
		l.live++
		l.opens++
		l.event("metadata-open")
		// Each new object is a separate modeled control-port generation.
		return &metadataOpen42Session{fakeAnchorSession: &fakeAnchorSession{namespace: seams.anchors, port: 0x40000000 + uint32(l.opens)}, ledger: l}, nil
	}
	openQueueTransport = func(port uint32) (nfqueueTransport, error) {
		q, err := openQueue(port)
		if err != nil {
			return nil, err
		}
		return &metadataOpen42Queue{nfqueueTransport: q, ledger: l}, nil
	}
	t.Cleanup(func() {
		bindAnchorTransactionSocket, closeAnchorTransactionSocket, openAnchorSession, openQueueTransport = bind, closeFD, openSession, openQueue
	})
	return l
}

func metadataOpen42Lease(t *testing.T, f Family) (*Engine, *Lease) {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatal(err)
	}
	source, dest := "192.0.2.1:40000", "198.51.100.7:443"
	if f == FamilyIPv6 {
		source, dest = "[2001:db8::1]:40000", "[2001:db8::2]:443"
	}
	l, err := e.NewAttempt(Intent{Family: f, Transport: TransportTCP, Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort(dest)})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLocalAddress(netip.MustParseAddrPort(source))
	t.Cleanup(func() { _ = e.Close() })
	return e, l
}

// Run default/zero first, independently of the topology regression below.
func TestMetadataOpenSessionDefaults(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	l := metadataOpen42Observe(t, seams)
	e, _ := metadataOpen42Lease(t, FamilyIPv4)
	for i := 0; i < 2; i++ {
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if l.opens != 0 || l.txOpens != 0 || len(seams.boundPortList()) != 0 || guardCount(seams) != 0 || e.ActiveLeases() != 0 {
		t.Fatal("zero-capture close acquired or retained resources")
	}
}

func TestMetadataOpenSessionSuccess(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			seams := installLinuxCaptureSeams(t, nil)
			l := metadataOpen42Observe(t, seams)
			for _, warm := range []bool{false, true} {
				e, lease := metadataOpen42Lease(t, family)
				l.mu.Lock()
				l.opening = true
				l.opens = 0
				l.closes = 0
				l.txOpens = 0
				l.txCloses = 0
				l.configs = 0
				l.dumps = 0
				l.generations = 0
				l.batches = 0
				l.familyGenerations = make(map[byte]int)
				l.events = nil
				l.mu.Unlock()
				if err := lease.StartCapture(); err != nil {
					t.Fatal(err)
				}
				c := lease.capture.(*linuxCapture)
				// Check the actual open return before any retirement transaction can affect
				// these exact counts. The final readback still has the Source41 D/G/B recipe.
				l.mu.Lock()
				l.opening = false
				wantB := 3
				if !warm {
					wantB = 9
				}
				if l.opens != 1 || l.closes != 1 || l.live != 0 || l.tx != 0 || l.txOpens != 1 || l.txCloses != 1 || l.configs != 4 {
					t.Errorf("open topology sessions=%d/%d live=%d tx=%d/%d live=%d CONFIG=%d", l.opens, l.closes, l.live, l.txOpens, l.txCloses, l.tx, l.configs)
				}
				if l.dumps != 49 || l.generations != 18 || l.batches != wantB {
					t.Errorf("readback/batch recipe D/G/B=%d/%d/%d want49/18/%d", l.dumps, l.generations, l.batches, wantB)
				}
				selected, other := byte(unix.NFPROTO_IPV4), byte(unix.NFPROTO_IPV6)
				if family == FamilyIPv6 {
					selected, other = other, selected
				}
				if l.familyGenerations[selected] != 12 || l.familyGenerations[other] != 6 {
					t.Errorf("both-family readbacks: %v", l.familyGenerations)
				}
				n := len(l.events)
				if n < 3 || l.events[n-3] != "dump" || l.events[n-2] != "metadata-close" || l.events[n-1] != "tx-close" {
					t.Errorf("final readback/Close order: %v", l.events)
				}
				t.Logf("MODEL family=%v warm=%v sessions=%d tx=%d CONFIG=%d D/G/B=%d/%d/%d", family, warm, l.opens, l.txOpens, l.configs, l.dumps, l.generations, l.batches)
				l.mu.Unlock()
				if !c.started || !c.outWitnessed || c.icmpQueue != 0 || c.overrideQnum != 0 || c.nl.boundPort() != c.outPort || c.outPort&nftQueuePortBit == 0 {
					t.Fatal("default witness/queue ownership changed")
				}
				// One immediately accepted inbound packet; no flow hold or injector path.
				payload := []byte("0123456789abcdef0123456789abcdef")
				packet := buildIPv4TCP(t, payload, 1000, tcpFlagACK|tcpFlagPSH)
				if family == FamilyIPv6 {
					packet = buildIPv6TCP(t, payload, 1000, tcpFlagACK|tcpFlagPSH)
				}
				if !seams.kernel.deliver(c.inQueue, fakePacketMessage(c.inQueue, 42, packet.Raw), 42) {
					t.Fatal("ordinary packet not delivered")
				}
				waitForCondition(t, "ordinary inbound verdict", func() bool { return len(seams.kernel.verdictsFor(c.inQueue, 42)) == 1 })
				verdicts := seams.kernel.verdictsFor(c.inQueue, 42)
				if verdicts[0].verdict != nfqueueVerdictAccept || verdicts[0].port != c.outPort {
					t.Fatal("ordinary verdict changed ownership/disposition")
				}
				for i := 0; i < 2; i++ {
					if err := lease.Close(nil); err != nil {
						t.Fatal(err)
					}
					if err := lease.WaitClosed(); err != nil {
						t.Fatal(err)
					}
					if err := lease.WaitCaptureRetired(); err != nil {
						t.Fatal(err)
					}
					if err := e.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if e.ActiveLeases() != 0 || guardCount(seams) != 0 || len(seams.kernel.boundQueues()) != 0 || !c.retired.Load() {
					t.Fatal("ordinary retirement retained ownership")
				}
				for _, f := range []Family{FamilyIPv4, FamilyIPv6} {
					if len(modelCaptureRecords(t, seams, f)) != 0 {
						t.Fatal("ordinary retirement left capture metadata")
					}
				}
			}
		})
	}
}
