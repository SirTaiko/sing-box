package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// fakeStreamAttachment is the hermetic seam around the OS-facing stream
// primitives. The production wiring uses *desync.StreamConfig; this type
// records the attachment lifecycle the bridge is responsible for.
type fakeStreamAttachment struct {
	mu       sync.Mutex
	prepares []fakePrepare
	wraps    []fakeWrap
	prepare  func(fd uintptr) error
	wrapErr  error
	wrapper  net.Conn
	// wrap, when set, builds the returned wrapper around the exact connection
	// the bridge handed over. It models a transformation wrapper that keeps the
	// underlying (admission-carrying) connection as its inner conn.
	wrap func(conn net.Conn) net.Conn
}

type fakePrepare struct {
	fd    uintptr
	facts desync.MatchFacts
}

type fakeWrap struct {
	facts desync.MatchFacts
	conn  net.Conn
}

func (f *fakeStreamAttachment) PrepareSocket(ctx context.Context, fd uintptr, facts desync.MatchFacts) error {
	f.mu.Lock()
	f.prepares = append(f.prepares, fakePrepare{fd: fd, facts: facts})
	prepare := f.prepare
	f.mu.Unlock()
	if prepare != nil {
		return prepare(fd)
	}
	return nil
}

func (f *fakeStreamAttachment) WrapConn(ctx context.Context, conn net.Conn, facts desync.MatchFacts) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wraps = append(f.wraps, fakeWrap{facts: facts, conn: conn})
	if f.wrapErr != nil {
		return nil, f.wrapErr
	}
	if f.wrap != nil {
		return f.wrap(conn), nil
	}
	if f.wrapper != nil {
		return f.wrapper, nil
	}
	return conn, nil
}

func (f *fakeStreamAttachment) counts() (prepares int, wraps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.prepares), len(f.wraps)
}

func (f *fakeStreamAttachment) prepareFacts() desync.MatchFacts {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.prepares) == 0 {
		return desync.MatchFacts{}
	}
	return f.prepares[0].facts
}

func (f *fakeStreamAttachment) wrapFacts() desync.MatchFacts {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.wraps) == 0 {
		return desync.MatchFacts{}
	}
	return f.wraps[0].facts
}

type trackedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *trackedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type countingBackend struct {
	opened atomic.Int32
	closed atomic.Int32
}

func (b *countingBackend) Name() string { return "counting" }

func (b *countingBackend) Open(lease *desync.Lease) (desync.Capture, error) {
	b.opened.Add(1)
	return &countingCapture{backend: b}, nil
}

type countingCapture struct {
	backend *countingBackend
}

func (c *countingCapture) Close() error {
	c.backend.closed.Add(1)
	return nil
}

func testPacketConfig(t *testing.T) *desync.Config {
	t.Helper()
	config, err := desync.Compile(&option.DirectDesyncOptions{
		Rules: []option.DirectDesyncRule{{
			Name:       "packet",
			Network:    []string{"tcp"},
			Port:       []uint16{443},
			Methods:    []string{"multisplit"},
			MultiSplit: &option.DirectDesyncSplitOptions{SplitPos: []string{"1"}},
		}},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testStreamRule(port uint16) option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{
		Name: "stream",
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Network:  []string{"tcp"},
			Port:     []uint16{port},
			Protocol: []string{"tls"},
		},
		Methods:   []string{"tls_record"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "host+2"},
	}
}

func TestCompileDirectDesyncMatrix(t *testing.T) {
	packetRule := option.DirectDesyncRule{
		Network:    []string{"tcp"},
		Port:       []uint16{443},
		Methods:    []string{"multisplit"},
		MultiSplit: &option.DirectDesyncSplitOptions{SplitPos: []string{"1"}},
	}
	disabled := false
	tests := []struct {
		name      string
		options   *option.DirectDesyncOptions
		engine    bool
		stream    bool
		stateOnly bool
		wantErr   string
	}{
		{name: "absent", options: nil},
		{name: "disabled", options: &option.DirectDesyncOptions{
			Enabled:     &disabled,
			Rules:       []option.DirectDesyncRule{packetRule},
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		}},
		{name: "packet only", options: &option.DirectDesyncOptions{
			Rules: []option.DirectDesyncRule{packetRule},
		}, engine: true},
		{name: "stream only", options: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		}, engine: true, stream: true, stateOnly: true},
		{name: "combined", options: &option.DirectDesyncOptions{
			Rules:       []option.DirectDesyncRule{packetRule},
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		}, engine: true, stream: true},
		{name: "enabled without rules", options: &option.DirectDesyncOptions{}, wantErr: "enabled without rules"},
		{name: "all rules disabled", options: &option.DirectDesyncOptions{
			Rules:       []option.DirectDesyncRule{{Name: "off", Disabled: true}},
			StreamRules: []option.DirectDesyncStreamRule{{Name: "off", Disabled: true}},
		}, wantErr: "enabled without enabled rules"},
		{name: "stream only with capture", options: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
			Capture:     &option.DirectDesyncCapture{},
		}, wantErr: "capture requires packet rules"},
		{name: "stream only with limits", options: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
			Limits:      &option.DirectDesyncLimits{MaxLeases: 2},
		}, wantErr: "limits require packet rules"},
		{name: "invalid stream network", options: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{{
				DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{Network: []string{"udp"}},
				Methods:                 []string{"http_tamper"},
				HTTPTamper:              &option.DirectDesyncStreamHTTPTamper{HostCase: true},
			}},
		}, wantErr: "TCP-only"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			engine, stream, err := compileDirectDesync(testCase.options, "")
			if testCase.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("error = %v, want %q", err, testCase.wantErr)
				}
				if engine != nil || stream != nil {
					t.Fatalf("failed compilation returned configs: engine=%v stream=%v", engine != nil, stream != nil)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (engine != nil) != testCase.engine {
				t.Fatalf("engine = %v, want %v", engine != nil, testCase.engine)
			}
			if (stream != nil) != testCase.stream {
				t.Fatalf("stream = %v, want %v", stream != nil, testCase.stream)
			}
			if engine != nil {
				defer engine.Close()
				if testCase.stateOnly {
					if engine.BackendName() != "state-only" {
						t.Fatalf("stream-only backend = %q, want state-only", engine.BackendName())
					}
					if len(engine.Config().Rules) != 0 {
						t.Fatalf("stream-only engine compiled packet rules: %d", len(engine.Config().Rules))
					}
				}
			}
		})
	}
}

func TestCheckDesyncDialerConflicts(t *testing.T) {
	engineConfig := testPacketConfig(t)
	streamConfig, err := desync.CompileStream([]option.DirectDesyncStreamRule{testStreamRule(443)}, "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := desync.NewEngine(engineConfig, &countingBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	cases := []struct {
		name    string
		options option.DialerOptions
		engine  *desync.Engine
		stream  *desync.StreamConfig
		wantErr string
	}{
		{name: "disabled ignores tfo", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}}},
		{name: "stream only allows tfo deferred", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}}, stream: streamConfig},
		{name: "stream only allows multipath", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPMultiPath: true}}, stream: streamConfig},
		{name: "stream only allows bind address no port", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindAddressNoPort: true}}, stream: streamConfig},
		{name: "packet rejects multipath", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPMultiPath: true}}, engine: engine, wantErr: "tcp_multipath"},
		{name: "packet allows tfo deferred", options: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}}, engine: engine},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := checkDesyncDialerConflicts(testCase.options, testCase.engine, testCase.stream)
			if testCase.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want %q", err, testCase.wantErr)
			}
		})
	}
}

func TestStreamOnlyAttemptLifecycle(t *testing.T) {
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.Domain = "example.com"
	leaseValue, err := hook.NewAttempt(ctx, dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	if lease.RequiresExclusiveBind() {
		t.Fatal("stream-only lease must keep the ordinary dialer bind path")
	}
	if err = lease.PrepareSocket(7); err != nil {
		t.Fatal(err)
	}
	prepares, wraps := fake.counts()
	if prepares != 1 {
		t.Fatalf("PrepareSocket calls = %d, want 1", prepares)
	}
	if wraps != 0 {
		t.Fatalf("WrapConn called before a successful dial")
	}
	facts := fake.prepareFacts()
	if facts.Transport != desync.TransportTCP || facts.Family != desync.FamilyIPv4 {
		t.Fatalf("preconnect facts: transport=%v family=%v", facts.Transport, facts.Family)
	}
	if facts.Destination != netip.MustParseAddr("203.0.113.7") || facts.Port != 443 {
		t.Fatalf("preconnect facts destination = %v:%d", facts.Destination, facts.Port)
	}
	if !facts.HostKnown || facts.Host != "example.com" {
		t.Fatalf("preconnect host = %q known=%v", facts.Host, facts.HostKnown)
	}
	if facts.Protocol != desync.ProtocolUnknown {
		t.Fatalf("preconnect protocol = %v, want unknown (no future SNI)", facts.Protocol)
	}

	client, server := net.Pipe()
	defer server.Close()
	tracked := &trackedConn{Conn: client}
	fake.wrapper = tracked
	attached, err := lease.AttachConn(client)
	if err != nil {
		t.Fatal(err)
	}
	if attached != tracked {
		t.Fatalf("AttachConn returned %T, want the configured wrapper", attached)
	}
	prepares, wraps = fake.counts()
	if prepares != 1 || wraps != 1 {
		t.Fatalf("calls after attach: prepares=%d wraps=%d", prepares, wraps)
	}
	wrapFacts := fake.wrapFacts()
	if wrapFacts.Port != 443 || wrapFacts.Destination != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("wrap facts destination = %v:%d", wrapFacts.Destination, wrapFacts.Port)
	}
	// Negative control: a second attachment must not wrap twice.
	if _, err = lease.AttachConn(client); err == nil {
		t.Fatal("second AttachConn must fail instead of wrapping twice")
	}
	if _, wraps = fake.counts(); wraps != 1 {
		t.Fatalf("WrapConn calls after duplicate attach = %d", wraps)
	}
	if err = attached.Close(); err != nil {
		t.Fatal(err)
	}
	if tracked.closes.Load() != 1 {
		t.Fatalf("wrapper closed %d times", tracked.closes.Load())
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestUDPAttemptHasNoStreamWork(t *testing.T) {
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "udp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.9"), 53),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	if lease.RequiresExclusiveBind() {
		t.Fatal("stream-only UDP lease must not own the bind")
	}
	if err = lease.PrepareSocket(11); err != nil {
		t.Fatal(err)
	}
	if prepares, wraps := fake.counts(); prepares != 0 || wraps != 0 {
		t.Fatalf("UDP attempt ran stream work: prepares=%d wraps=%d", prepares, wraps)
	}
	conn := &trackedConn{Conn: nopConn{}}
	attached, err := lease.AttachConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	if attached != conn {
		t.Fatal("UDP AttachConn must return the original connection")
	}
	if prepares, wraps := fake.counts(); prepares != 0 || wraps != 0 {
		t.Fatalf("UDP attach ran stream work: prepares=%d wraps=%d", prepares, wraps)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestPacketUDPLeaseStillCaptures(t *testing.T) {
	backend := &countingBackend{}
	engine, err := desync.NewEngine(testPacketConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	hook := &desyncHook{engine: engine, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "udp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.10"), 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if backend.opened.Load() != 1 {
		t.Fatalf("UDP capture opened %d times", backend.opened.Load())
	}
	conn := &trackedConn{Conn: nopConn{}}
	attached, err := lease.AttachConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	if attached != conn {
		t.Fatal("UDP AttachConn must keep the existing connection identity")
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("UDP capture closed %d times", backend.closed.Load())
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("UDP lease not released: %d active", engine.ActiveLeases())
	}
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, errors.New("not implemented") }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

func TestCombinedAttemptOwnsWrapperAndCapture(t *testing.T) {
	fake := &fakeStreamAttachment{}
	backend := &countingBackend{}
	engine, err := desync.NewEngine(testPacketConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	hook := &desyncHook{engine: engine, stream: fake, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.8"), 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	if !lease.RequiresExclusiveBind() {
		t.Fatal("combined lease must own the exclusive bind")
	}
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if backend.opened.Load() != 1 {
		t.Fatalf("capture opened %d times", backend.opened.Load())
	}
	client, server := net.Pipe()
	defer server.Close()
	var tracked *trackedConn
	fake.wrap = func(conn net.Conn) net.Conn {
		// The transformation wrapper stays outside the admission-carrying
		// connection; it must close exactly the connection it was given.
		tracked = &trackedConn{Conn: conn}
		return tracked
	}
	attached, err := lease.AttachConn(client)
	if err != nil {
		t.Fatal(err)
	}
	inner := attached
	if tracked != nil {
		inner = tracked.Conn
	}
	if _, isLeaseConn := inner.(*leaseConn); !isLeaseConn {
		t.Fatalf("combined attachment must own the capture lease inside the stream wrapper, got %T", inner)
	}
	if err = attached.Close(); err != nil {
		t.Fatal(err)
	}
	if tracked.closes.Load() != 1 {
		t.Fatalf("stream wrapper closed %d times", tracked.closes.Load())
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("capture closed %d times", backend.closed.Load())
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("lease retained after connection close: %d", engine.ActiveLeases())
	}
	if err = attached.Close(); err != nil {
		t.Fatal(err)
	}
	// The transformation wrapper owns the outer close; the admission-carrying
	// connection underneath must close its lease exactly once no matter how
	// often that wrapper is closed.
	if err = inner.(*leaseConn).Close(); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("leaseConn close is not idempotent: capture closed %d times", backend.closed.Load())
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestAttachFailureIsTerminal(t *testing.T) {
	fake := &fakeStreamAttachment{wrapErr: errors.New("stream wrapper rejected")}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.9"), 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	client, server := net.Pipe()
	defer server.Close()
	tracked := &trackedConn{Conn: client}
	attached, err := lease.AttachConn(tracked)
	if err == nil {
		t.Fatal("a wrapper failure must fail the attempt")
	}
	if attached != nil {
		t.Fatalf("failed attach returned a connection: %T", attached)
	}
	if tracked.closes.Load() != 1 {
		t.Fatalf("failed attach closed the native connection %d times", tracked.closes.Load())
	}
}

func TestRealStreamWrapperLoopbackTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	streamConfig, err := desync.CompileStream([]option.DirectDesyncStreamRule{{
		Name: "http-tamper",
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Network:  []string{"tcp"},
			Port:     []uint16{port},
			Protocol: []string{"http"},
		},
		Methods:    []string{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 4096)
		total := 0
		for {
			n, readErr := conn.Read(buffer[total:])
			total += n
			if readErr != nil {
				break
			}
			if strings.Contains(string(buffer[:total]), "\r\n\r\n") {
				break
			}
		}
		received <- string(buffer[:total])
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := streamConfig.WrapConn(context.Background(), client, desync.MatchFacts{
		Family:      desync.FamilyIPv4,
		Transport:   desync.TransportTCP,
		Destination: netip.MustParseAddr("127.0.0.1"),
		Port:        port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrapped.Write([]byte("GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err = wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		want := "GET / HTTP/1.1\r\nhost: Example.COM\r\n\r\n"
		if got != want {
			t.Fatalf("wire bytes = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loopback peer did not observe the transformed request")
	}
}

func TestUDPListenerAttemptWithoutDestination(t *testing.T) {
	backend := &countingBackend{}
	engine, err := desync.NewEngine(testPacketConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{engine: engine, stream: fake, lifetime: context.Background()}
	source := netip.MustParseAddrPort("0.0.0.0:5353")
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network: "udp",
		Source:  source,
	})
	if err != nil {
		t.Fatalf("a bound UDP listener must be able to own a lease: %v", err)
	}
	lease := leaseValue.(*desyncLease)
	if !lease.RequiresExclusiveBind() {
		t.Fatal("packet listener lease must own the bind")
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if backend.opened.Load() != 1 {
		t.Fatalf("listener capture opened %d times", backend.opened.Load())
	}
	if prepares, wraps := fake.counts(); prepares != 0 || wraps != 0 {
		t.Fatalf("UDP listener ran stream work: prepares=%d wraps=%d", prepares, wraps)
	}
	conn := &trackedConn{Conn: nopConn{}}
	attached, err := lease.AttachConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	if attached != conn {
		t.Fatal("UDP listener AttachPacketConn path must keep the connection identity")
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 || engine.ActiveLeases() != 0 {
		t.Fatalf("listener lease not released: closed=%d active=%d", backend.closed.Load(), engine.ActiveLeases())
	}
	// Stream-only listeners need no engine at all and must not error either.
	streamOnly := &desyncHook{stream: fake, lifetime: context.Background()}
	leaseValue, err = streamOnly.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network: "udp",
		Source:  source,
	})
	if err != nil {
		t.Fatalf("stream-only UDP listener must not require a packet engine: %v", err)
	}
	if err = leaseValue.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAttemptsStillRequireResolvedDestination(t *testing.T) {
	hook := &desyncHook{stream: &fakeStreamAttachment{}, lifetime: context.Background()}
	if _, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{Network: "tcp"}); err == nil {
		t.Fatal("a TCP attempt without a resolved destination must fail")
	}
	if _, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{Network: "udp"}); err == nil {
		t.Fatal("a UDP attempt without a destination or local endpoint must fail")
	}
}

func TestRealStreamWrapperLeavesUDPUntouched(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "udp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 53),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseValue.(*desyncLease)
	conn, err := net.Dial("udp", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	attached, err := lease.AttachConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("dns-payload-unchanged")
	if _, err = attached.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 64)
	n, _, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatalf("UDP payload = %q, want %q", buffer[:n], payload)
	}
	if prepares, wraps := fake.counts(); prepares != 0 || wraps != 0 {
		t.Fatalf("UDP connection ran stream work: prepares=%d wraps=%d", prepares, wraps)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}
