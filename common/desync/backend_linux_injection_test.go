//go:build linux

package desync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// These tests exercise the real inject/sendInjected control flow. Only the
// namespace syscalls and raw socket syscalls are modelled: no network objects,
// setns, packets, kernel delivery or native namespace success is claimed.
type injectionModel struct {
	t           *testing.T
	mu          sync.Mutex
	capture     *linuxCapture
	target      int
	current     map[int]int
	origins     map[int]int
	events      []string
	tids        []int
	fail        string
	restoreErr  error
	sendEntered chan struct{}
	sendRelease chan struct{}
	packet      []byte
	family      Family
}

var errInjectionModel = errors.New("injection model operation failure")

func installInjectionModel(t *testing.T, c *linuxCapture, packet []byte) *injectionModel {
	t.Helper()
	m := &injectionModel{t: t, capture: c, target: c.owner.nsFD, current: make(map[int]int), origins: make(map[int]int), packet: append([]byte(nil), packet...)}
	parsed, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	m.family = parsed.Family
	wantMark := c.lease.socketMarkValue
	if capture := c.lease.engine.Config().Capture; capture.fwmarkSet {
		wantMark |= int(capture.fwmark)
	}
	get, set := getThreadNetns, setThreadNetns
	open, optInt, optString := openInjectionSocket, setInjectionSockoptInt, setInjectionSockoptString
	bind, send, closeFD := bindInjectionSocket, sendInjectionPacket, closeInjectionSocket
	t.Cleanup(func() {
		getThreadNetns, setThreadNetns = get, set
		openInjectionSocket, setInjectionSockoptInt, setInjectionSockoptString = open, optInt, optString
		bindInjectionSocket, sendInjectionPacket, closeInjectionSocket = bind, send, closeFD
	})
	getThreadNetns = func() (netns.NsHandle, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.events = append(m.events, "save")
		if m.fail == "save" {
			return -1, errInjectionModel
		}
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			m.origins[fd] = unix.Gettid()
		}
		return netns.NsHandle(fd), err
	}
	setThreadNetns = func(ns netns.NsHandle) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		tid := unix.Gettid()
		if int(ns) == m.target {
			m.events = append(m.events, "enter")
			m.tids = append(m.tids, tid)
			if m.fail == "enter" {
				return errInjectionModel
			}
			m.current[tid] = m.target
			return nil
		}
		m.events = append(m.events, "restore")
		if m.origins[int(ns)] != tid {
			t.Errorf("restore switched OS thread: fd%d tid%d owner%d", ns, tid, m.origins[int(ns)])
		}
		if m.restoreErr != nil {
			return m.restoreErr
		}
		m.current[tid] = 0
		return nil
	}
	openInjectionSocket = func(domain, kind, protocol int) (int, error) {
		m.check("socket")
		want := unix.AF_INET
		if m.family == FamilyIPv6 {
			want = unix.AF_INET6
		}
		if domain != want || kind != unix.SOCK_RAW|unix.SOCK_CLOEXEC || protocol != unix.IPPROTO_RAW {
			t.Errorf("raw socket args: %d %d %d", domain, kind, protocol)
		}
		if m.fail == "socket" {
			return -1, errInjectionModel
		}
		return 1000000, nil
	}
	setInjectionSockoptInt = func(fd, level, name, value int) error {
		kind := "option"
		switch name {
		case unix.IP_HDRINCL:
			if level == unix.IPPROTO_IP {
				kind = "hdrincl"
				if value != 1 {
					t.Errorf("IP_HDRINCL=%d", value)
				}
			}
		case unix.SO_MARK:
			if level == unix.SOL_SOCKET {
				kind = "mark"
				if value != wantMark {
					t.Errorf("mark=%x", value)
				}
			}
		case unix.SO_PRIORITY:
			if level == unix.SOL_SOCKET {
				kind = "priority"
				if value != int(c.anchor.tag) {
					t.Errorf("priority=%x", value)
				}
			}
		case unix.IP_FREEBIND, unix.IPV6_FREEBIND:
			kind = "freebind"
		}
		m.check(kind)
		if m.fail == kind {
			return errInjectionModel
		}
		return nil
	}
	setInjectionSockoptString = func(fd, level, name int, value string) error {
		m.check("device")
		if level != unix.SOL_SOCKET || name != unix.SO_BINDTODEVICE || value != "model-device" {
			t.Errorf("device args %d %d %q", level, name, value)
		}
		if m.fail == "device" {
			return errInjectionModel
		}
		return nil
	}
	bindInjectionSocket = func(fd int, sa unix.Sockaddr) error {
		m.check("bind")
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			if netip.AddrFrom4(a.Addr) != parsed.Src || a.Port != 0 {
				t.Errorf("source bind=%+v", a)
			}
		case *unix.SockaddrInet6:
			if netip.AddrFrom16(a.Addr) != parsed.Src || a.Port != 0 {
				t.Errorf("source bind=%+v", a)
			}
		default:
			t.Errorf("source bind type %T", sa)
		}
		if m.fail == "bind" {
			return errInjectionModel
		}
		return nil
	}
	sendInjectionPacket = func(fd int, b []byte, flags int, sa unix.Sockaddr) error {
		m.check("send")
		if !bytes.Equal(b, m.packet) || flags != 0 {
			t.Errorf("send bytes/flags changed")
		}
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			if netip.AddrFrom4(a.Addr) != parsed.Dst || a.Port != int(parsed.DstPort) {
				t.Errorf("destination=%+v", a)
			}
		case *unix.SockaddrInet6:
			if netip.AddrFrom16(a.Addr) != parsed.Dst || a.Port != 0 || a.ZoneId != 0 {
				t.Errorf("raw IPv6 destination=%+v, want port0/scope0 and %s (transport port%d stays in packet)", a, parsed.Dst, parsed.DstPort)
			}
		default:
			t.Errorf("destination type %T", sa)
		}
		if m.sendEntered != nil {
			close(m.sendEntered)
			<-m.sendRelease
		}
		if m.fail == "send" {
			return errInjectionModel
		}
		return nil
	}
	closeInjectionSocket = func(fd int) error {
		m.check("close")
		if fd != 1000000 {
			t.Errorf("close wrong fd %d", fd)
		}
		return nil
	}
	return m
}

func (m *injectionModel) check(kind string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tid := unix.Gettid()
	m.events = append(m.events, kind)
	if m.current[tid] != m.target {
		m.t.Errorf("%s in ambient model namespace on tid%d, want owner fd%d", kind, tid, m.target)
	}
	if syscall.ForkLock.TryLock() {
		syscall.ForkLock.Unlock()
		m.t.Errorf("%s outside fork-read token", kind)
	}
	if m.capture.rawMu.TryLock() {
		m.capture.rawMu.Unlock()
		m.t.Errorf("%s outside rawMu serialization", kind)
	}
	if m.capture.lease.mu.TryLock() {
		m.capture.lease.mu.Unlock()
	} else {
		m.t.Errorf("%s under Lease lock", kind)
	}
	if m.capture.lease.engine.mu.TryLock() {
		m.capture.lease.engine.mu.Unlock()
	} else {
		m.t.Errorf("%s under Engine lock", kind)
	}
}
func (m *injectionModel) assertEvents(want []string) {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !reflect.DeepEqual(m.events, want) {
		m.t.Errorf("operation order=%v, want %v", m.events, want)
	}
	for fd := range m.origins {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			m.t.Errorf("saved origin fd%d not closed: %v", fd, err)
		}
	}
}

func injectionFixture(t *testing.T, family Family) (*linuxCapture, []byte) {
	t.Helper()
	src, dst := "192.0.2.10:12345", "198.51.100.20:23456"
	if family == FamilyIPv6 {
		src, dst = "[2001:db8::10]:12345", "[2001:db8::20]:23456"
	}
	p := udpPeerPacket(t, netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), []byte{0, 1, 2, 3, 0xff})
	if family == FamilyIPv4 {
		binary.BigEndian.PutUint16(p.Raw[4:6], 0x3142)
		p.Raw[10], p.Raw[11] = 0, 0
		binary.BigEndian.PutUint16(p.Raw[10:12], inetChecksum(p.Raw[:20], 0))
	}
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	l := &Lease{engine: &Engine{config: &Config{}}, socketMarkValue: 0x123, socketDeviceValue: "model-device"}
	l.engine.config.Capture.bindFix4 = true
	l.engine.config.Capture.bindFix6 = true
	l.engine.config.Capture.fwmarkSet = true
	l.engine.config.Capture.fwmark = 0x400
	return &linuxCapture{owner: &anchorOwner{nsFD: fd, refs: 1}, lease: l, anchor: captureAnchor{tag: 0x53590042}}, p.Raw
}

func injectionSuccessEvents(f Family) []string {
	e := []string{"save", "enter", "socket"}
	if f == FamilyIPv4 {
		e = append(e, "hdrincl")
	}
	return append(e, "freebind", "bind", "mark", "device", "priority", "send", "close", "restore")
}

func TestLinuxInjectionOwnerNamespace(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(strconv.Itoa(int(family)), func(t *testing.T) {
			c, p := injectionFixture(t, family)
			m := installInjectionModel(t, c, p)
			if err := c.inject(p); err != nil {
				t.Fatal(err)
			}
			m.assertEvents(injectionSuccessEvents(family))
			if !c.lease.lowHopSent.Load() {
				t.Error("successful injection not recorded")
			}
			if !syscall.ForkLock.TryLock() {
				t.Fatal("fork token not released")
			}
			syscall.ForkLock.Unlock()
		})
	}
}

func TestLinuxInjectionFailuresRestoreAndClose(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, kind := range []string{"save", "enter", "socket", "hdrincl", "priority", "send"} {
			if family == FamilyIPv6 && kind == "hdrincl" {
				continue
			}
			t.Run(fmt.Sprintf("%d/%s", family, kind), func(t *testing.T) {
				c, p := injectionFixture(t, family)
				m := installInjectionModel(t, c, p)
				m.fail = kind
				if err := c.inject(p); !errors.Is(err, errInjectionModel) {
					t.Errorf("operation error lost: %v", err)
				}
				want := []string{"save"}
				if kind != "save" {
					want = append(want, "enter")
				}
				if kind != "save" && kind != "enter" {
					all := injectionSuccessEvents(family)
					for _, e := range all[2:] {
						if e == "close" || e == "restore" {
							break
						}
						want = append(want, e)
						if e == kind {
							break
						}
					}
					if kind != "socket" {
						want = append(want, "close")
					}
					want = append(want, "restore")
				}
				m.assertEvents(want)
				if c.lease.lowHopSent.Load() {
					t.Error("failed operation counted as injection")
				}
			})
		}
	}
}

func TestLinuxInjectionIgnoredOptionsPreserved(t *testing.T) {
	for _, kind := range []string{"freebind", "bind", "mark", "device"} {
		t.Run(kind, func(t *testing.T) {
			c, p := injectionFixture(t, FamilyIPv4)
			m := installInjectionModel(t, c, p)
			m.fail = kind
			if err := c.inject(p); err != nil {
				t.Errorf("previously ignored %s failure became fatal: %v", kind, err)
			}
			m.assertEvents(injectionSuccessEvents(FamilyIPv4))
		})
	}
}

func TestLinuxInjectionRestoreFailureDiscardsHelper(t *testing.T) {
	for _, tc := range []struct {
		family   Family
		failSend bool
	}{{FamilyIPv4, false}, {FamilyIPv4, true}, {FamilyIPv6, false}, {FamilyIPv6, true}} {
		t.Run(fmt.Sprintf("%d/%t", tc.family, tc.failSend), func(t *testing.T) {
			c, p := injectionFixture(t, tc.family)
			m := installInjectionModel(t, c, p)
			restore := errors.New("model restore failure")
			m.restoreErr = restore
			if tc.failSend {
				m.fail = "send"
			}
			type result struct {
				err           error
				caller, after int
			}
			done := make(chan result)
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				caller := unix.Gettid()
				err := c.inject(p)
				done <- result{err, caller, unix.Gettid()}
			}()
			r := <-done
			if !errors.Is(r.err, restore) || (tc.failSend && !errors.Is(r.err, errInjectionModel)) {
				t.Errorf("restore/operation errors not joined: %v", r.err)
			}
			m.assertEvents(injectionSuccessEvents(tc.family))
			m.mu.Lock()
			tids := append([]int(nil), m.tids...)
			callerNS := m.current[r.after]
			m.mu.Unlock()
			if r.caller != r.after || callerNS != 0 {
				t.Errorf("caller contaminated/migrated: %+v ns%d", r, callerNS)
			}
			if len(tids) != 1 {
				t.Fatalf("helper enter tids=%v", tids)
			}
			tid := tids[0]
			t.Logf("caller_tid=%d helper_tid=%d process_pid=%d", r.caller, tid, os.Getpid())
			if tid == r.caller {
				t.Error("restore failure ran on caller, not disposable helper")
			}
			if tid == os.Getpid() {
				// Go's mexit parks m0 permanently rather than exiting the Linux
				// thread-group leader. It is still discarded from the pool.
				var probes sync.WaitGroup
				for i := 0; i < 64; i++ {
					probes.Add(1)
					go func() {
						defer probes.Done()
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()
						if unix.Gettid() == tid {
							t.Error("contaminated m0 reused")
						}
					}()
				}
				probes.Wait()
				t.Log("runtime m0: permanently parked, not expected to disappear from /proc")
				return
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				_, err := os.Stat(fmt.Sprintf("/proc/self/task/%d", tid))
				if errors.Is(err, os.ErrNotExist) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("contaminated helper tid%d was not discarded", tid)
				}
				runtime.Gosched()
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestLinuxInjectionConcurrentCallersSerialize(t *testing.T) {
	c, p := injectionFixture(t, FamilyIPv6)
	m := installInjectionModel(t, c, p)
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.inject(p); err != nil {
				t.Errorf("concurrent inject: %v", err)
			}
		}()
	}
	wg.Wait()
	var want []string
	for i := 0; i < n; i++ {
		want = append(want, injectionSuccessEvents(FamilyIPv6)...)
	}
	m.assertEvents(want)
}

// The existing dispatch gate owns callback admission/join. Retirement must not
// release the owner's pinned FD while the actual synchronous Sendto is active.
func TestLinuxInjectionCloseWaitsForSend(t *testing.T) {
	q := newFakeNFQueueConn("injection-close", 0, nil)
	installLinuxCaptureSeams(t, q)
	cfg, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"port":[23456],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(cfg, NewNativeBackend())
	if err != nil {
		t.Fatal(err)
	}
	src, dst := netip.MustParseAddrPort("192.0.2.10:12345"), netip.MustParseAddrPort("198.51.100.20:23456")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(src)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	c := lease.capture.(*linuxCapture)
	c.lease.setSocketMark(0x123)
	c.lease.setSocketDevice("model-device")
	c.lease.engine.config.Capture.bindFix4 = true
	p := udpPeerPacket(t, src, dst, []byte("lifetime")).Raw
	m := installInjectionModel(t, c, p)
	m.sendEntered = make(chan struct{})
	m.sendRelease = make(chan struct{})
	sent := make(chan error)
	if !c.dispatch.beginDispatch() {
		t.Fatal("dispatch closed")
	}
	go func() { err := c.inject(p); c.dispatch.endDispatch(); sent <- err }()
	<-m.sendEntered
	closed := make(chan error)
	go func() {
		err := lease.Close(nil)
		if err == nil {
			err = lease.WaitCaptureRetired()
		}
		closed <- err
	}()
	select {
	case err := <-closed:
		t.Fatalf("Close passed active Sendto: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := unix.FcntlInt(uintptr(m.target), unix.F_GETFD, 0); err != nil {
		t.Errorf("owner fd closed during Sendto: %v", err)
	}
	close(m.sendRelease)
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if c.owner.nsFD != -1 || !c.retired.Load() {
		t.Errorf("owner/retirement incomplete fd%d retired%v", c.owner.nsFD, c.retired.Load())
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
}
