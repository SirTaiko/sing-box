package listener

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

func TestTCPAdmissionExactLimit(t *testing.T) {
	admission := newTCPAdmission(2)
	if !admission.acquire() || !admission.acquire() {
		t.Fatal("expected both tokens")
	}
	if admission.acquire() {
		t.Fatal("the limit must reject a third token")
	}
	admission.release()
	if !admission.acquire() {
		t.Fatal("a released token must be reusable")
	}
}

func TestAdmissionConnReleaseOnce(t *testing.T) {
	admission := newTCPAdmission(1)
	client, server := net.Pipe()
	defer server.Close()
	if !admission.acquire() {
		t.Fatal("expected the token")
	}
	conn := newAdmissionConn(client, admission)
	if conn.AdmissionCloseHandler() == nil {
		t.Fatal("expected an onClose handler")
	}
	conn.AdmissionCloseHandler()(nil)
	if admission.count.Load() != 0 {
		t.Fatalf("onClose must release, count=%d", admission.count.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if admission.count.Load() != 0 {
		t.Fatalf("release must be idempotent, count=%d", admission.count.Load())
	}
	// The token is usable again after the exact-once release.
	if !admission.acquire() {
		t.Fatal("expected a token after release")
	}
	admission.release()
}

type closeWriteConn struct {
	*fakeSyscallConn
	closeWriteCalls int
	closeReadCalls  int
}

func (c *closeWriteConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

func (c *closeWriteConn) CloseRead() error {
	c.closeReadCalls++
	return nil
}

func TestAdmissionConnForwardsCapabilities(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	base := &closeWriteConn{fakeSyscallConn: &fakeSyscallConn{Conn: client, rawConn: &fakeRawConn{fd: 1}}}
	admission := newTCPAdmission(1)
	if !admission.acquire() {
		t.Fatal("expected the token")
	}
	conn := newAdmissionConn(base, admission)
	if _, ok := conn.Conn.(syscall.Conn); !ok {
		t.Fatal("test connection must expose syscall.Conn")
	}
	if _, err := conn.SyscallConn(); err != nil {
		t.Fatalf("SyscallConn must be forwarded: %v", err)
	}
	if err := conn.CloseWrite(); err != nil || base.closeWriteCalls != 1 {
		t.Fatalf("CloseWrite not forwarded: calls=%d err=%v", base.closeWriteCalls, err)
	}
	if err := conn.CloseRead(); err != nil || base.closeReadCalls != 1 {
		t.Fatalf("CloseRead not forwarded: calls=%d err=%v", base.closeReadCalls, err)
	}
	_ = conn.Close()
}

func TestAcceptHandlerLimitClosesBeforeDispatch(t *testing.T) {
	admission := newTCPAdmission(1)
	handler := &tcpAcceptHandler{admission: admission, logger: logger.NOP()}
	firstClient, firstServer := net.Pipe()
	defer firstServer.Close()
	admitted, ok := handler.accept(firstClient)
	if !ok {
		t.Fatal("the first connection must be admitted")
	}
	secondClient, secondServer := net.Pipe()
	defer secondServer.Close()
	if _, ok := handler.accept(secondClient); ok {
		t.Fatal("the second connection must be rejected")
	}
	// The rejected connection is closed, not dispatched.
	secondServer.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buffer := make([]byte, 1)
	if _, err := secondServer.Read(buffer); err == nil {
		t.Fatal("the rejected connection must be closed")
	}
	if admission.count.Load() != 1 {
		t.Fatalf("rejected connection changed the count: %d", admission.count.Load())
	}
	// Closing the admitted connection releases the exact token.
	admitted.Close()
	if admission.count.Load() != 0 {
		t.Fatalf("close must release the token: %d", admission.count.Load())
	}
}

type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   chan struct{}
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), closed: make(chan struct{}), once: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}

func TestMultiListenerSharedAdmissionAcrossSockets(t *testing.T) {
	first := newFakeListener()
	second := newFakeListener()
	handler := &tcpAcceptHandler{admission: newTCPAdmission(1), logger: logger.NOP()}
	multi := newTCPMultiListener([]net.Listener{first, second}, handler)
	defer multi.Close()
	firstClient, firstServer := net.Pipe()
	defer firstServer.Close()
	first.conns <- firstClient
	accepted, err := multi.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// A connection on the other bind socket competes for the same token and
	// is closed instead of dispatched.
	secondClient, secondServer := net.Pipe()
	defer secondServer.Close()
	second.conns <- secondClient
	acceptedSecond := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := multi.Accept()
		if acceptErr == nil {
			acceptedSecond <- conn
		}
	}()
	select {
	case <-acceptedSecond:
		t.Fatal("the shared cap must not admit a second connection")
	case <-time.After(100 * time.Millisecond):
	}
	// Releasing the first token lets the next accept proceed.
	accepted.Close()
	select {
	case <-acceptedSecond:
		t.Fatal("the rejected connection must not be dispatched after release")
	case <-time.After(100 * time.Millisecond):
	}
	// A fresh connection on either socket is admitted after the release.
	thirdClient, thirdServer := net.Pipe()
	defer thirdServer.Close()
	second.conns <- thirdClient
	select {
	case conn := <-acceptedSecond:
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("expected a connection after the token release")
	}
}

func TestMultiListenerShutdownClosesOnlyOwnedSockets(t *testing.T) {
	first := newFakeListener()
	second := newFakeListener()
	multi := newTCPMultiListener([]net.Listener{first, second}, &tcpAcceptHandler{})
	if err := multi.Close(); err != nil {
		t.Fatal(err)
	}
	for index, listener := range []*fakeListener{first, second} {
		select {
		case <-listener.closed:
		default:
			t.Fatalf("listener %d was not closed", index)
		}
	}
	if _, err := multi.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

func tcpBindingList(bindings ...option.TCPListenBinding) *option.TCPListenBindingList {
	list := option.TCPListenBindingList(bindings)
	return &list
}

func ipv4Binding(t *testing.T, value string) option.TCPListenBinding {
	t.Helper()
	address := mustAddr(t, value)
	optionAddress := badoption.Addr(address)
	return option.TCPListenBinding{Address: &optionAddress, IPVersion: 4}
}

func TestListenTCPBindingsRollback(t *testing.T) {
	first := newFakeListener()
	second := newFakeListener()
	closedFirst := false
	listenCalls := 0
	bindings := []option.TCPListenBinding{
		ipv4Binding(t, "192.0.2.1"),
		ipv4Binding(t, "192.0.2.2"),
	}
	listener := &Listener{
		ctx:    context.Background(),
		logger: logger.NOP(),
		listenOptions: option.ListenOptions{
			TCPListenBindings: tcpBindingList(bindings...),
		},
		bindSource: staticSource(),
		listenFunc: func(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error) {
			listenCalls++
			switch listenCalls {
			case 1:
				return &trackedListener{fakeListener: first, onClose: func() { closedFirst = true }}, nil
			case 2:
				return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EADDRNOTAVAIL}
			default:
				return second, nil
			}
		},
	}
	if _, err := listener.ListenTCP(); err == nil {
		t.Fatal("expected the second bind failure")
	}
	if listenCalls != 2 {
		t.Fatalf("unexpected listen calls: %d", listenCalls)
	}
	if !closedFirst {
		t.Fatal("a later bind failure must close earlier sockets")
	}
	select {
	case <-second.closed:
		t.Fatal("a listener that was never acquired must stay untouched")
	default:
	}
}

type trackedListener struct {
	*fakeListener
	onClose func()
}

func (l *trackedListener) Close() error {
	if l.onClose != nil {
		l.onClose()
	}
	return l.fakeListener.Close()
}

func TestListenTCPLegacyFastPathUnchanged(t *testing.T) {
	base := newFakeListener()
	listener := &Listener{
		ctx:    context.Background(),
		logger: logger.NOP(),
		listenFunc: func(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error) {
			return base, nil
		},
	}
	result, err := listener.ListenTCP()
	if err != nil {
		t.Fatal(err)
	}
	if result != net.Listener(base) {
		t.Fatalf("option-absent path must return the exact listener, got %T", result)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenTCPBindingsConflicts(t *testing.T) {
	bindings := tcpBindingList(ipv4Binding(t, "192.0.2.1"))
	legacy := &Listener{
		ctx:    context.Background(),
		logger: logger.NOP(),
		listenOptions: option.ListenOptions{
			Listen:            addrOption("192.0.2.9"),
			TCPListenBindings: bindings,
		},
	}
	if _, err := legacy.ListenTCP(); err == nil {
		t.Fatal("legacy listen plus bindings must conflict")
	}
	systemProxy := &Listener{
		ctx:            context.Background(),
		logger:         logger.NOP(),
		setSystemProxy: true,
		listenOptions:  option.ListenOptions{TCPListenBindings: bindings},
	}
	if _, err := systemProxy.ListenTCP(); err == nil {
		t.Fatal("set_system_proxy plus bindings must conflict")
	}
	udp := &Listener{
		ctx:           context.Background(),
		logger:        logger.NOP(),
		network:       []string{"tcp", "udp"},
		listenOptions: option.ListenOptions{TCPListenBindings: bindings},
	}
	if _, err := udp.ListenTCP(); err == nil {
		t.Fatal("bindings on a UDP-listening protocol must be rejected")
	}
	badLimit := uint16(0)
	maxConnections := &Listener{
		ctx:           context.Background(),
		logger:        logger.NOP(),
		listenOptions: option.ListenOptions{TCPMaxConnections: &badLimit},
	}
	if _, err := maxConnections.ListenTCP(); err == nil {
		t.Fatal("tcp_max_connections=0 must be rejected")
	}
	tooMany := uint16(10001)
	maxConnections.listenOptions.TCPMaxConnections = &tooMany
	if _, err := maxConnections.ListenTCP(); err == nil {
		t.Fatal("tcp_max_connections>10000 must be rejected")
	}
}

func TestListenTCPExplicitAddressRetryWithinBudget(t *testing.T) {
	clock := &fakeBindClock{now: time.Unix(100, 0)}
	attempts := 0
	binding := ipv4Binding(t, "192.0.2.1")
	binding.WaitIP = badoption.Duration(2 * time.Second)
	listener := &Listener{
		ctx:        context.Background(),
		logger:     logger.NOP(),
		bindSource: staticSource(),
		bindClock:  clock,
		listenOptions: option.ListenOptions{
			TCPListenBindings: tcpBindingList(binding),
		},
		listenFunc: func(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error) {
			attempts++
			if attempts < 3 {
				return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EADDRNOTAVAIL}
			}
			return newFakeListener(), nil
		},
	}
	result, err := listener.ListenTCP()
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("expected three attempts inside the budget, got %d", attempts)
	}
	_ = result.Close()
	// No budget: exactly one attempt even on EADDRNOTAVAIL.
	clock = &fakeBindClock{now: time.Unix(100, 0)}
	attempts = 0
	listener = &Listener{
		ctx:        context.Background(),
		logger:     logger.NOP(),
		bindSource: staticSource(),
		bindClock:  clock,
		listenOptions: option.ListenOptions{
			TCPListenBindings: tcpBindingList(ipv4Binding(t, "192.0.2.1")),
		},
		listenFunc: func(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error) {
			attempts++
			return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EADDRNOTAVAIL}
		},
	}
	if _, err = listener.ListenTCP(); err == nil {
		t.Fatal("expected a bind error")
	}
	if attempts != 1 {
		t.Fatalf("wait_ip=0 must not retry, attempts=%d", attempts)
	}
}
