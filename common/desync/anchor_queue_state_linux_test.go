//go:build linux

package desync

// MODEL only: production Lease -> Open -> rollback/Close, over the existing
// in-memory nft/queue transports and regular-file reports. No native sockets,
// traffic, fork, process death or kernel probes. The same tests compile on 36.
import (
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type preparationFailure struct {
	*fakeNFQueueConn
	t          *testing.T
	seams      *linuxCaptureSeams
	kind       string
	targetBind int
	binds      int
	target     uint16
	hit        bool
	attempts   []netlink.Message
	published  *anchorManifestRecord
	key        string
	foreign    *fakeNFQueueConn
}

// Explicit model receipt: the rejecting branch made no BIND effect. Unknown
// branches below never return this interface, even if their errno is EPERM.
type modelQueueConfigRejection struct{ error }

func (e *modelQueueConfigRejection) Unwrap() error         { return e.error }
func (e *modelQueueConfigRejection) queueConfigRejection() {}

func (f *preparationFailure) Execute(m netlink.Message) ([]netlink.Message, error) {
	f.attempts = append(f.attempts, m)
	q, cmd, ok := parseNFQueueConfig(m)
	if !ok {
		f.t.Fatal("MODEL: malformed command")
	}
	if cmd == nfqCfgCmdBind {
		f.binds++
		if f.binds == f.targetBind {
			f.target = q
			records := modelCaptureRecords(f.t, f.seams, FamilyIPv4)
			if len(records) != 1 {
				f.t.Fatal("MODEL: failure must follow exact publication")
			}
			for k, r := range records {
				f.key, f.published = k, r
			}
			if f.published.port == nil || f.published.port.record.phase != "w" {
				f.t.Fatal("MODEL: failure before w")
			}
		}
	}
	if f.target != 0 && q == f.target {
		reject := func() ([]netlink.Message, error) {
			return nil, &modelQueueConfigRejection{unix.EPERM}
		}
		if cmd == nfqCfgCmdBind {
			switch f.kind {
			case "bind-rejected":
				f.hit = true
				return reject()
			case "bind-lost-applied":
				f.hit = true
				if _, err := f.fakeNFQueueConn.Execute(m); err != nil {
					return nil, err
				}
				return nil, os.ErrDeadlineExceeded
			case "bind-lost-absent":
				f.hit = true
				return nil, os.ErrDeadlineExceeded
			case "bind-syscall":
				f.hit = true
				return nil, &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvfrom", unix.EPERM), Sequence: m.Header.Sequence}
			case "bind-unmatched":
				f.hit = true
				return nil, &netlink.OpError{Op: "receive", Err: unix.EPERM, Sequence: m.Header.Sequence + 1}
			}
		}
		if cmd == 0 && len(m.Data) > 4 && !f.hit {
			f.hit = true
			return reject()
		}
		if cmd == nfqCfgCmdUnbind {
			if f.kind == "unbind-lost-absent" {
				if _, err := f.fakeNFQueueConn.Execute(m); err != nil {
					return nil, err
				}
				return nil, os.ErrDeadlineExceeded
			}
			if f.kind == "unbind-lost-bound" {
				return nil, os.ErrDeadlineExceeded
			}
			if f.kind == "unbind-rejected" {
				return reject()
			}
			replies, err := f.fakeNFQueueConn.Execute(m)
			if err == nil && f.kind == "config-rollback-foreign" {
				// A later listener acquires the successfully released number. No own
				// CONFIG/UNBIND is licensed for this new owner during rollback.
				f.foreign = newFakeNFQueueConn("later-owner", 0x8000ffff, f.seams.kernel)
				err = f.seams.kernel.control(f.foreign, q, nfqCfgCmdBind)
			}
			return replies, err
		}
	}
	return f.fakeNFQueueConn.Execute(m)
}

func TestSource37RemainingQueuePreparation(t *testing.T) {
	for _, which := range []string{"in", "icmp", "zero-in"} {
		for _, kind := range []string{"bind-rejected", "config-rollback", "config-rollback-foreign", "bind-lost-applied", "bind-lost-absent", "bind-syscall", "bind-unmatched", "unbind-lost-absent", "unbind-lost-bound", "unbind-rejected"} {
			t.Run(which+"/"+kind, func(t *testing.T) {
				data := newFakeNFQueueConn("partial-preparation", 0, nil)
				seams := installLinuxCaptureSeams(t, data)
				f := &preparationFailure{fakeNFQueueConn: data, t: t, seams: seams, kind: kind, targetBind: 2}
				_, lease := newLinuxCaptureLease(t, 16600)
				if which == "zero-in" {
					_, lease = newLinuxCaptureLease(t, 0)
				}
				if which == "icmp" {
					lease = newFilteredICMPLease(t, 16601)
					f.targetBind = 3
				}
				openQueueTransport = func(port uint32) (nfqueueTransport, error) {
					if _, err := seams.dial(port); err != nil {
						return nil, err
					}
					return f, nil
				}
				err := lease.StartCapture()
				if err == nil || !f.hit {
					t.Fatalf("MODEL: intended preparation failure not reached: %v hit=%v", err, f.hit)
				}
				safe := kind == "bind-rejected" || kind == "config-rollback" || kind == "config-rollback-foreign"
				if safe {
					if err := lease.Close(nil); err != nil {
						t.Fatalf("MODEL F-01: known partial preparation cannot retire: %v", err)
					}
					if err := lease.WaitCaptureRetired(); err != nil {
						t.Fatal(err)
					}
					if lease.engine.ActiveLeases() != 0 || data.closings() != 1 || guardCount(seams) != 0 || qnumLive(int(f.published.record.ports.out)) || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 0 {
						t.Fatal("MODEL F-01: known partial preparation kept owner/socket/metadata/charge")
					}
					want := []uint16{f.published.record.ports.out}
					if which == "icmp" {
						want = append(want, f.published.record.ports.in)
					}
					expectEveryBoundQueueReceivedOnce(t, orderedOwnQueueReceipts(t, f.attempts), want)
					if countQueueCommand(t, f.attempts, f.published.record.ports.out, nfqCfgCmdUnbind) != 0 {
						t.Fatal("MODEL: witness unbound instead of socket retirement")
					}
					unbinds := countQueueCommand(t, f.attempts, f.target, nfqCfgCmdUnbind)
					wantUnbinds := 1
					if kind == "bind-rejected" {
						wantUnbinds = 0
					}
					if unbinds != wantUnbinds {
						t.Fatalf("MODEL: controls for rejected/released target: unbind=%d want=%d", unbinds, wantUnbinds)
					}
					if f.foreign != nil && seams.kernel.owner(f.target) != f.foreign {
						t.Fatal("MODEL: foreign listener changed")
					}
				} else {
					lease.mu.Lock()
					c, ok := lease.capture.(*linuxCapture)
					lease.mu.Unlock()
					if !ok {
						t.Fatal("MODEL: uncertain preparation published nil capture/retirement")
					}
					if c.outPort != f.published.port.record.port || c.queue != f.published.record.ports.out || c.overrideQnum != int(c.queue) || !c.outWitnessed || !c.owner.retainedState() || c.retired.Load() {
						t.Fatal("MODEL: unknown effect lost exact witness/owner")
					}
					before := guardResidueSnapshot(seams, data)
					attempts := len(f.attempts)
					for i := 0; i < 2; i++ {
						if err := lease.Close(nil); err == nil {
							t.Error("MODEL: unknown queue effect reported successful Close")
						}
						if err := lease.WaitCaptureRetired(); err == nil {
							t.Error("MODEL: unknown queue effect reported retirement")
						}
						if lease.engine.ActiveLeases() != 1 || !qnumLive(int(c.queue)) || data.closings() != 0 || guardCount(seams) != 1 {
							t.Error("MODEL: uncertainty lost charge/reservation/socket/guard")
						}
						if !reflect.DeepEqual(before, guardResidueSnapshot(seams, data)) || len(f.attempts) != attempts {
							t.Error("MODEL: repeated Close changed retained exact identity or retried controls")
						}
					}
					if !reflect.DeepEqual(modelCaptureRecords(t, seams, FamilyIPv4)[f.key], f.published) {
						t.Fatal("MODEL: uncertain m+p changed")
					}
				}
			})
		}
	}
}

func TestSource37QnumZeroReuse(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	_, first := newLinuxCaptureLease(t, 0)
	if err := first.StartCapture(); err != nil {
		t.Fatal(err)
	}
	c := first.capture.(*linuxCapture)
	if c.queue != 0 || !qnumLive(0) {
		t.Fatal("MODEL: zero was not explicitly reserved")
	}
	if err := first.Close(nil); err != nil {
		t.Fatal(err)
	}
	if qnumLive(0) {
		t.Error("MODEL F-03: retired queue zero remains locally reserved")
	}
	_, second := newLinuxCaptureLease(t, 0)
	if err := second.StartCapture(); err != nil {
		t.Fatalf("MODEL F-03: 0 -> Close -> 0 refused: %v", err)
	}
	if err := first.Close(nil); err != nil {
		t.Fatal(err)
	}
	if !qnumLive(0) {
		t.Fatal("MODEL: repeated old Close freed new zero reservation")
	}
	if err := second.Close(nil); err != nil {
		t.Fatal(err)
	}
	if qnumLive(0) || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 0 {
		t.Fatal("MODEL: zero retirement leaked")
	}
}

func TestSource37ZeroPrepublicationCleanup(t *testing.T) {
	for _, stage := range []string{"before-m", "before-w", "unknown-m"} {
		t.Run(stage, func(t *testing.T) {
			seams := installLinuxCaptureSeams(t, nil)
			_, lease := newLinuxCaptureLease(t, 0)
			if stage == "before-m" {
				readProcessIdentity = func() (processIdentity, error) { return processIdentity{}, unix.EPERM }
			}
			if stage == "before-w" {
				openQueueTransport = func(uint32) (nfqueueTransport, error) { return nil, unix.EPERM }
			}
			if stage == "unknown-m" {
				var unreadable atomic.Bool
				openAnchorSession = func() (anchorSession, error) {
					return &guardFailureSession{fakeAnchorSession: &fakeAnchorSession{namespace: seams.anchors, port: 0x40000033}, kind: "m-ack-unknown", unreadable: &unreadable, gate: func() {}}, nil
				}
			}
			if err := lease.StartCapture(); err == nil {
				t.Fatal("MODEL: failure not reached")
			}
			err := lease.Close(nil)
			if stage == "unknown-m" {
				if err == nil || !qnumLive(0) || lease.engine.ActiveLeases() != 1 {
					t.Fatal("MODEL: unknown metadata freed zero/charge")
				}
			} else if err != nil || qnumLive(0) || lease.engine.ActiveLeases() != 0 {
				t.Fatalf("MODEL F-03: safe prepublication zero cleanup failed: %v reserved=%v", err, qnumLive(0))
			}
		})
	}
}
