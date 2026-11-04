//go:build linux

package desync

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Success-only MODEL. Every raw/namespace syscall is replaced before a caller
// runs. Only /dev/null origin handles are real; no network, fork, error or
// retirement schedule is exercised. Do not add this file to a whole-suite run.
type batchSuccessSocket struct {
	family         int
	mark, priority int
	device         string
	source         netip.Addr
}
type batchSuccessModel struct {
	t                                      *testing.T
	capture                                *linuxCapture
	current                                int
	origin                                 int
	saves, enters, restores, opens, closes int
	live                                   map[int]*batchSuccessSocket
	sends                                  [][]byte
	sentFD                                 []int
	settings                               []batchSuccessSocket
	events                                 []string
	afterSend                              func(int)
}

func batchSuccessInstall(t *testing.T, c *linuxCapture) *batchSuccessModel {
	t.Helper()
	m := &batchSuccessModel{t: t, capture: c, live: make(map[int]*batchSuccessSocket)}
	oldOnce := linuxForkSafetyOnce
	get, set := getThreadNetns, setThreadNetns
	open, opt, str := openInjectionSocket, setInjectionSockoptInt, setInjectionSockoptString
	bind, send, closeFD := bindInjectionSocket, sendInjectionPacket, closeInjectionSocket
	t.Cleanup(func() {
		linuxForkSafetyOnce = oldOnce
		getThreadNetns, setThreadNetns = get, set
		openInjectionSocket, setInjectionSockoptInt, setInjectionSockoptString = open, opt, str
		bindInjectionSocket, sendInjectionPacket, closeInjectionSocket = bind, send, closeFD
	})
	linuxForkSafetyOnce = sync.OnceValue(func() error { return nil })
	getThreadNetns = func() (netns.NsHandle, error) {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		m.origin = fd
		m.saves++
		m.events = append(m.events, "save")
		return netns.NsHandle(fd), nil
	}
	setThreadNetns = func(fd netns.NsHandle) error {
		if int(fd) == m.capture.owner.nsFD {
			m.current = int(fd)
			m.enters++
			m.events = append(m.events, "enter")
		} else {
			if int(fd) != m.origin {
				t.Errorf("wrong origin %d", fd)
			}
			m.current = 0
			m.restores++
			m.events = append(m.events, "restore")
		}
		return nil
	}
	openInjectionSocket = func(family, kind, proto int) (int, error) {
		if m.current != m.capture.owner.nsFD || len(m.live) != 0 {
			t.Errorf("socket outside context or more than one slot")
		}
		if kind != unix.SOCK_RAW|unix.SOCK_CLOEXEC || proto != unix.IPPROTO_RAW {
			t.Errorf("socket args %d/%d", kind, proto)
		}
		m.opens++
		fd := 1000000 + m.opens
		m.live[fd] = &batchSuccessSocket{family: family}
		m.events = append(m.events, "socket")
		return fd, nil
	}
	setInjectionSockoptInt = func(fd, level, name, value int) error {
		s := m.live[fd]
		if s == nil {
			t.Errorf("option without socket")
			return nil
		}
		if level == unix.SOL_SOCKET {
			switch name {
			case unix.SO_MARK:
				s.mark = value
			case unix.SO_PRIORITY:
				s.priority = value
			default:
				t.Errorf("unexpected SOL_SOCKET option %d", name)
			}
		} else if !(level == unix.IPPROTO_IP && (name == unix.IP_HDRINCL || name == unix.IP_FREEBIND) || level == unix.IPPROTO_IPV6 && name == unix.IPV6_FREEBIND) || value != 1 {
			t.Errorf("unexpected IP option %d/%d/%d", level, name, value)
		}
		return nil
	}
	setInjectionSockoptString = func(fd, level, name int, value string) error {
		if level != unix.SOL_SOCKET || name != unix.SO_BINDTODEVICE {
			t.Errorf("unexpected string option")
		}
		m.live[fd].device = value
		return nil
	}
	bindInjectionSocket = func(fd int, sa unix.Sockaddr) error {
		switch v := sa.(type) {
		case *unix.SockaddrInet4:
			m.live[fd].source = netip.AddrFrom4(v.Addr)
			if v.Port != 0 {
				t.Error("bind port")
			}
		case *unix.SockaddrInet6:
			m.live[fd].source = netip.AddrFrom16(v.Addr)
			if v.Port != 0 {
				t.Error("bind port")
			}
		default:
			t.Errorf("bind address %T", sa)
		}
		return nil
	}
	sendInjectionPacket = func(fd int, b []byte, flags int, sa unix.Sockaddr) error {
		if m.current != m.capture.owner.nsFD {
			t.Errorf("send outside target")
		}
		if m.capture.rawMu.TryLock() {
			m.capture.rawMu.Unlock()
			t.Error("send outside raw serialization")
		}
		batchSuccessLocks(t, m.capture.lease)
		p, err := ParsePacket(b)
		if err != nil {
			t.Error(err)
			return err
		}
		s := m.live[fd]
		if s == nil {
			t.Error("send without socket")
			return nil
		}
		if flags != 0 {
			t.Error("send flags")
		}
		switch v := sa.(type) {
		case *unix.SockaddrInet4:
			if p.Family != FamilyIPv4 || s.family != unix.AF_INET || v.Addr != p.Dst.As4() || v.Port != int(p.DstPort) {
				t.Errorf("v4 destination %+v", v)
			}
		case *unix.SockaddrInet6:
			if p.Family != FamilyIPv6 || s.family != unix.AF_INET6 || v.Addr != p.Dst.As16() || v.Port != 0 || v.ZoneId != 0 {
				t.Errorf("v6 destination %+v", v)
			}
		default:
			t.Errorf("destination %T", sa)
		}
		m.sends = append(m.sends, append([]byte(nil), b...))
		m.sentFD = append(m.sentFD, fd)
		m.settings = append(m.settings, *s)
		m.events = append(m.events, "send")
		if m.afterSend != nil {
			m.afterSend(len(m.sends))
		}
		return nil
	}
	closeInjectionSocket = func(fd int) error {
		if m.live[fd] == nil {
			t.Errorf("unknown socket %d", fd)
		}
		delete(m.live, fd)
		m.closes++
		m.events = append(m.events, "close")
		return nil
	}
	return m
}
func batchSuccessLocks(t *testing.T, l *Lease) {
	t.Helper()
	for _, mu := range []*sync.Mutex{&l.mu, &l.engine.mu} {
		if mu.TryLock() {
			mu.Unlock()
		} else {
			t.Error("callback under Lease/Engine lock")
		}
	}
	if !l.engine.configMu.TryLock() {
		t.Error("callback under config lock")
	} else {
		l.engine.configMu.Unlock()
	}
	if l.tcpFlow != nil {
		if l.tcpFlow.mu.TryLock() {
			l.tcpFlow.mu.Unlock()
		} else {
			t.Error("callback under TCP flow lock")
		}
	}
	for _, f := range l.udpFlows {
		if f.mu.TryLock() {
			f.mu.Unlock()
		} else {
			t.Error("callback under UDP flow lock")
		}
	}
}

type batchSuccessRandom struct{}

func (batchSuccessRandom) Uint32() uint32 { return 0x31415926 }
func (batchSuccessRandom) Intn(n int) int { return 0 }

func batchSuccessLease(t *testing.T, config string, p *Packet) *Lease {
	t.Helper()
	oldRandom := DefaultRand
	DefaultRand = batchSuccessRandom{}
	t.Cleanup(func() { DefaultRand = oldRandom })
	cfg, err := Compile(enabledOption(config), "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, stateOnlyBackend{})
	if err != nil {
		t.Fatal(err)
	}
	l, err := e.NewAttempt(Intent{Family: p.Family, Transport: p.Transport, Source: netip.AddrPortFrom(p.Src, p.SrcPort), Destination: netip.AddrPortFrom(p.Dst, p.DstPort)})
	if err != nil {
		t.Fatal(err)
	}
	// No native capture is opened. All fixtures finish their successful holds.
	return l
}
func batchSuccessPacket(t *testing.T, f Family, payload []byte) *Packet {
	t.Helper()
	src, dst := "192.0.2.10:12345", "198.51.100.20:23456"
	if f == FamilyIPv6 {
		src, dst = "[2001:db8::10]:12345", "[2001:db8::20]:23456"
	}
	return udpPeerPacket(t, netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), payload)
}

const batchSTUNConfig = `{"enabled":true,"rules":[{"network":["udp"],"port":[23456],"protocol":["stun"],"methods":["fake"],"fake":{"repeats":6,"payloads":[{"protocol":"stun","hex":"0123456789abcdef"}]}}]}`

func batchSTUNPacket(t *testing.T, f Family) *Packet {
	return batchSuccessPacket(t, f, []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

type batchSuccessVerdicts struct {
	nfqueueConn
	t        *testing.T
	m        *batchSuccessModel
	messages []netlink.Message
}

func (q *batchSuccessVerdicts) boundPort() uint32 { return 0x80000042 }

func (q *batchSuccessVerdicts) Send(v netlink.Message) (netlink.Message, error) {
	if q.m.current != 0 || len(q.m.live) != 0 || q.m.enters != q.m.restores {
		q.t.Error("disposition before synchronous batch receipt")
	}
	q.messages = append(q.messages, v)
	return v, nil
}
func TestSource38BatchDefaults(t *testing.T) {
	// Assert untouched defaults before any success model installation.
	if reflect.ValueOf(openInjectionSocket).Pointer() != reflect.ValueOf(unix.Socket).Pointer() || reflect.ValueOf(setThreadNetns).Pointer() != reflect.ValueOf(netns.Set).Pointer() {
		t.Fatal("default seam changed")
	}
	p := batchSTUNPacket(t, FamilyIPv4)
	l := batchSuccessLease(t, `{"enabled":true,"rules":[{"network":["udp"],"methods":[]}]}`, p)
	if v := l.HandlePacket(p.Raw, DirectionOutbound, nil, nil); v != VerdictPass || l.Err() != nil {
		t.Fatalf("default nil/empty disposition %v %v", v, l.Err())
	}
}
func TestSource38BatchActualCaller(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			p := batchSTUNPacket(t, family)
			l := batchSuccessLease(t, batchSTUNConfig, p)
			want, err := PlanUDP(l.engine.Config().Rules[0], p)
			if err != nil || len(want.Packets) != 6 {
				t.Fatalf("plan %v %v", want, err)
			}
			c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590042}, queue: 12000, inQueue: 12001, dispatch: newCaptureDispatchGate()}
			m := batchSuccessInstall(t, c)
			q := &batchSuccessVerdicts{t: t, m: m}
			c.nl = q
			if !c.handleBatch([]netlink.Message{fakePacketMessage(c.queue, 71, p.Raw)}) {
				t.Fatal("packet callback rejected")
			}
			if !reflect.DeepEqual(m.sends, want.Packets) {
				t.Fatal("ordered planned bytes differ")
			}
			if len(q.messages) != 1 {
				t.Fatalf("dispositions %d", len(q.messages))
			}
			attrs, err := netlink.UnmarshalAttributes(q.messages[0].Data[4:])
			if err != nil {
				t.Fatal(err)
			}
			if len(attrs) != 1 || binary.BigEndian.Uint32(attrs[0].Data[:4]) != nfqueueVerdictAccept || binary.BigEndian.Uint32(attrs[0].Data[4:]) != 71 {
				t.Fatalf("original disposition %+v", attrs)
			}
			if !l.lowHopSent.Load() || l.Err() != nil {
				t.Fatalf("successful-send observation/diagnostic %v", l.Err())
			}
			t.Logf("MODEL actual caller: sends=%d sockets=%d saves=%d setns=%d raw_closes=%d total_closes=%d", len(m.sends), m.opens, m.saves, m.enters+m.restores, m.closes, m.closes+m.saves)
			if m.opens != 1 || m.saves != 1 || m.enters != 1 || m.restores != 1 || m.closes != 1 {
				t.Fatalf("want one operation for six packets, events=%v", m.events)
			}
		})
	}
}

func TestSource38BatchProfile03(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			base := batchSTUNPacket(t, family)
			p := udpPeerPacket(t, netip.AddrPortFrom(base.Src, base.SrcPort), netip.AddrPortFrom(base.Dst, 19302), base.Payload)
			l := batchSuccessLease(t, batchSTUNConfig, p)
			// The existing complete profile and authentic payload assets, not a
			// smaller synthetic fake. No product/native backend is opened.
			l.engine.config = qa519CompileProfile(t, "03")
			want, err := PlanUDP(l.engine.config.Rules[1], p)
			if err != nil || len(want.Packets) != 6 {
				t.Fatalf("profile03 plan: %v", err)
			}
			for _, raw := range want.Packets {
				packet, err := ParsePacket(raw)
				if err != nil || len(packet.Payload) != 1200 {
					t.Fatalf("profile03 fake length: %v", err)
				}
			}
			c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590043}, queue: 12000, inQueue: 12001, dispatch: newCaptureDispatchGate()}
			m := batchSuccessInstall(t, c)
			q := &batchSuccessVerdicts{t: t, m: m}
			c.nl = q
			if !c.handleBatch([]netlink.Message{fakePacketMessage(c.queue, 72, p.Raw)}) {
				t.Fatal("profile03 callback")
			}
			if !reflect.DeepEqual(m.sends, want.Packets) || m.opens != 1 || m.saves != 1 || len(q.messages) != 1 {
				t.Fatalf("profile03 sends=%d sockets=%d saves=%d dispositions=%d", len(m.sends), m.opens, m.saves, len(q.messages))
			}
			t.Logf("M-B01 profile03: exact six 1200B fake payloads; sockets=%d setns=%d total_closes=%d", m.opens, m.enters+m.restores, m.closes+m.saves)
		})
	}
}

func TestSource38BatchPublicFallback(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, disposition := range []string{"fake", "empty", "modify", "nil"} {
			t.Run(network+"/"+disposition, func(t *testing.T) {
				p := batchSTUNPacket(t, FamilyIPv4)
				config := batchSTUNConfig
				if network == "tcp" {
					p = buildIPv4TCP(t, []byte("GET / HTTP/1.1\r\nHost: batch.example\r\n\r\n"), 1000, tcpFlagACK|tcpFlagPSH)
					config = `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],"fake":{"repeats":6,"payloads":[{"protocol":"http","hex":"123456"}]}}]}`
				}
				if disposition == "empty" {
					config = fmt.Sprintf(`{"enabled":true,"rules":[{"network":[%q],"methods":[]}]}`, network)
				}
				if disposition == "modify" {
					config = fmt.Sprintf(`{"enabled":true,"rules":[{"network":[%q],"methods":[],"orig":{"ttl":9}}]}`, network)
				}
				l := batchSuccessLease(t, config, p)
				var got [][]byte
				inject := Injector(func(raw []byte) error { batchSuccessLocks(t, l); got = append(got, bytes.Clone(raw)); return nil })
				if disposition == "nil" {
					inject = nil
				}
				v := l.HandlePacket(p.Raw, DirectionOutbound, inject, func(Verdict, string, []byte) { t.Error("unexpected immediate completer") })
				if l.Err() != nil {
					t.Fatalf("fallback diagnostic %v", l.Err())
				}
				if disposition == "modify" {
					modified, err := ParsePacket(l.TakeModified(DirectionOutbound))
					if v != VerdictModify || err != nil || modified.TTL != 9 {
						t.Fatalf("modified disposition %v/%v", v, err)
					}
				} else if v != VerdictPass {
					t.Fatalf("fallback verdict %v", v)
				}
				if disposition == "fake" {
					if len(got) != 6 {
						t.Fatalf("fallback calls %d", len(got))
					}
					var want *Batch
					var err error
					if network == "tcp" {
						_, _, facts := protocolFacts(p.Payload)
						want, err = PlanTCP(l.engine.config.Rules[0], p, p.Payload, 0, facts)
					} else {
						want, err = PlanUDP(l.engine.config.Rules[0], p)
					}
					if err != nil || !reflect.DeepEqual(got, want.Packets) {
						t.Fatalf("fallback bytes %v", err)
					}
				} else if len(got) != 0 {
					t.Fatalf("empty/nil callbacks %d", len(got))
				}
			})
		}
	}
	t.Run("descriptor-empty", func(t *testing.T) {
		for _, i := range []packetInjection{{}, {single: func([]byte) error { t.Error("empty single called"); return nil }}, {batch: func([][]byte) (int, error) { t.Error("empty batch called"); return 0, nil }}} {
			if n, err := i.send(nil); n != 0 || err != nil {
				t.Fatalf("empty %d/%v", n, err)
			}
		}
	})
}

func TestSource38BatchChunks(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, n := range []int{0, 1, 6, 64, 65, 129} {
			t.Run(fmt.Sprintf("%d/%d", family, n), func(t *testing.T) {
				p := batchSTUNPacket(t, family)
				l := batchSuccessLease(t, batchSTUNConfig, p)
				c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590042}}
				m := batchSuccessInstall(t, c)
				var packets [][]byte
				for i := 0; i < n; i++ {
					packets = append(packets, batchSuccessPacket(t, family, []byte{byte(i), byte(i >> 8)}).Raw)
				}
				got, err := c.injectBatch(packets)
				h := (n + 63) / 64
				if err != nil || got != n || !reflect.DeepEqual(m.sends, packets) {
					t.Fatalf("batch %d: got%d/%v bytes%t", n, got, err, reflect.DeepEqual(m.sends, packets))
				}
				if m.saves != h || m.enters != h || m.restores != h || m.opens != h || m.closes != h || m.current != 0 {
					t.Fatalf("chunks want%d events=%v", h, m.events)
				}
				sends := 0
				for _, event := range m.events {
					if event == "send" {
						sends++
					}
					if event == "restore" {
						if sends < 1 || sends > 64 {
							t.Fatalf("chunk sends %d", sends)
						}
						sends = 0
					}
				}
				if sends != 0 || l.lowHopSent.Load() != (n > 0) {
					t.Fatal("terminal/send accounting")
				}
				t.Logf("M-B04 N=%d H=%d sends=%d", n, h, len(m.sends))
			})
		}
	}
}

func TestSource38BatchSettings(t *testing.T) {
	for _, name := range []string{"family", "mark-to-zero", "device-to-empty-to-other", "bind-source", "bind-off", "snapshot", "capture-owner"} {
		t.Run(name, func(t *testing.T) {
			p := batchSTUNPacket(t, FamilyIPv4)
			l := batchSuccessLease(t, batchSTUNConfig, p)
			c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590042}}
			m := batchSuccessInstall(t, c)
			packets := [][]byte{p.Raw, p.Raw, p.Raw}
			wantOpen := 3
			switch name {
			case "family":
				packets[1] = batchSTUNPacket(t, FamilyIPv6).Raw
			case "mark-to-zero":
				l.socketMarkValue = 0x123
				m.afterSend = func(n int) {
					l.mu.Lock()
					defer l.mu.Unlock()
					if n == 1 {
						l.socketMarkValue = 0
					} else {
						l.socketMarkValue = 0x456
					}
				}
			case "device-to-empty-to-other":
				l.socketDeviceValue = "device-A"
				m.afterSend = func(n int) {
					l.mu.Lock()
					defer l.mu.Unlock()
					if n == 1 {
						l.socketDeviceValue = ""
					} else {
						l.socketDeviceValue = "device-B"
					}
				}
			case "bind-source":
				l.engine.config.Capture.bindFix4 = true
				packets[1] = udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.11:12345"), netip.AddrPortFrom(p.Dst, p.DstPort), p.Payload).Raw
			case "bind-off":
				l.engine.config.Capture.bindFix4 = true
				wantOpen = 2
				m.afterSend = func(n int) {
					if n == 1 {
						cfg := *l.engine.Config()
						cfg.Capture.bindFix4 = false
						l.engine.configMu.Lock()
						l.engine.config = &cfg
						l.engine.configMu.Unlock()
					}
				}
			case "snapshot":
				m.afterSend = func(int) {
					cfg := *l.engine.Config()
					l.engine.configMu.Lock()
					l.engine.config = &cfg
					l.engine.configMu.Unlock()
				}
			case "capture-owner":
				for index := 0; index < 2; index++ {
					if index == 1 {
						other := batchSuccessLease(t, batchSTUNConfig, p)
						other.socketMarkValue = 0x789
						other.socketDeviceValue = "other-device"
						c = &linuxCapture{lease: other, owner: &anchorOwner{nsFD: 900002}, anchor: captureAnchor{tag: 0x53590043}}
						m.capture = c
					}
					if n, err := c.injectBatch(packets); n != 3 || err != nil {
						t.Fatalf("capture%d %d/%v", index, n, err)
					}
				}
				if m.opens != 2 || m.saves != 2 || len(m.sends) != 6 || m.settings[0].priority == m.settings[3].priority || m.settings[0].mark != 0 || m.settings[3].mark != 0x789 || m.settings[3].device != "other-device" {
					t.Fatalf("capture context bleed: %+v", m.settings)
				}
				return
			}
			if n, err := c.injectBatch(packets); n != 3 || err != nil {
				t.Fatalf("settings batch %d/%v", n, err)
			}
			if m.opens != wantOpen || m.saves != 1 || !reflect.DeepEqual(m.sends, packets) {
				t.Fatalf("settings opens=%d want%d events=%v", m.opens, wantOpen, m.events)
			}
			switch name {
			case "mark-to-zero":
				if m.settings[0].mark != 0x123 || m.settings[1].mark != 0 || m.settings[2].mark != 0x456 {
					t.Errorf("marks %+v", m.settings)
				}
			case "device-to-empty-to-other":
				if m.settings[0].device != "device-A" || m.settings[1].device != "" || m.settings[2].device != "device-B" {
					t.Errorf("devices %+v", m.settings)
				}
			case "bind-source":
				for i, b := range packets {
					parsed, _ := ParsePacket(b)
					if m.settings[i].source != parsed.Src {
						t.Error("source bleed")
					}
				}
			case "bind-off":
				if !m.settings[0].source.IsValid() || m.settings[1].source.IsValid() || m.settings[2].source.IsValid() {
					t.Error("bind-off inherited source")
				}
			}
			// A second ordinary operation always starts fresh, even at the same key.
			m.afterSend = nil
			before := m.opens
			if n, err := c.injectBatch(packets[:1]); n != 1 || err != nil || m.opens != before+1 || m.saves != 2 {
				t.Fatal("cross-call reuse")
			}
		})
	}
}

func TestSource38BatchRawBytes(t *testing.T) {
	for _, kind := range []string{"udp4", "udp6", "tcp4-options"} {
		t.Run(kind, func(t *testing.T) {
			family := FamilyIPv4
			if kind == "udp6" {
				family = FamilyIPv6
			}
			p := batchSTUNPacket(t, family)
			l := batchSuccessLease(t, batchSTUNConfig, p)
			c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590042}}
			m := batchSuccessInstall(t, c)
			var packets [][]byte
			for i := 0; i < 6; i++ {
				var raw []byte
				if kind == "tcp4-options" {
					tcp := buildIPv4TCP(t, []byte{byte(i), 0xff}, 1000+uint32(i), tcpFlagACK|tcpFlagPSH)
					ttl := uint8(10 + i)
					var err error
					raw, err = BuildTCP(tcp, tcp.Payload, TCPMods{TTL: ttl, TSIncrement: int32(i)})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					dst := netip.AddrPortFrom(p.Dst.Next(), uint16(24000+i))
					raw = udpPeerPacket(t, netip.AddrPortFrom(p.Src, p.SrcPort), dst, []byte{byte(i), 0xff}).Raw
					if family == FamilyIPv4 {
						raw[8] = byte(10 + i)
						raw[1] = byte(i << 2)
						raw[10], raw[11] = 0, 0
						binary.BigEndian.PutUint16(raw[10:12], inetChecksum(raw[:20], 0))
					} else {
						raw[7] = byte(10 + i)
						raw[0] = 0x60 | byte(i)
					}
				}
				packets = append(packets, raw)
			}
			before := make([][]byte, len(packets))
			for i := range packets {
				before[i] = bytes.Clone(packets[i])
			}
			if n, err := c.injectBatch(packets); n != 6 || err != nil || m.opens != 1 || !reflect.DeepEqual(m.sends, before) || !reflect.DeepEqual(packets, before) {
				t.Fatalf("raw bytes %d/%v opens%d", n, err, m.opens)
			}
		})
	}
}
