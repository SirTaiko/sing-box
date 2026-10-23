package listener

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type socketCall struct {
	kind  string
	value int
}

type socketFake struct {
	calls       []socketCall
	setErr      error
	getValue    int
	getErr      error
	timeoutErr  error
	setFailKind string
}

func (f *socketFake) setSocketBuffer(fd uintptr, option int, value int) error {
	kind := "rcvbuf"
	if option == socketOptionSendBuffer {
		kind = "sndbuf"
	}
	f.calls = append(f.calls, socketCall{kind: kind, value: value})
	if f.setFailKind == kind {
		return f.setErr
	}
	return nil
}

func (f *socketFake) getSocketBuffer(fd uintptr, option int) (int, error) {
	kind := "rcvbuf"
	if option == socketOptionSendBuffer {
		kind = "sndbuf"
	}
	f.calls = append(f.calls, socketCall{kind: "get-" + kind})
	return f.getValue, f.getErr
}

func (f *socketFake) setUserTimeout(fd uintptr, millis int) error {
	f.calls = append(f.calls, socketCall{kind: "timeout", value: millis})
	return f.timeoutErr
}

func installSocketFake(t *testing.T) *socketFake {
	t.Helper()
	fake := &socketFake{}
	originalSet := tcpSetSocketBuffer
	originalGet := tcpGetSocketBuffer
	originalTimeout := tcpSetUserTimeout
	tcpSetSocketBuffer = fake.setSocketBuffer
	tcpGetSocketBuffer = fake.getSocketBuffer
	tcpSetUserTimeout = fake.setUserTimeout
	t.Cleanup(func() {
		tcpSetSocketBuffer = originalSet
		tcpGetSocketBuffer = originalGet
		tcpSetUserTimeout = originalTimeout
	})
	return fake
}

func TestApplyTCPSocketOptionsOrderAndValues(t *testing.T) {
	fake := installSocketFake(t)
	options := option.TCPOptions{ReceiveBufferSize: 100_000, SendBufferSize: 50_000, UserTimeoutMillis: 20_000}
	if err := applyTCPSocketOptions(7, options); err != nil {
		t.Fatal(err)
	}
	expected := []socketCall{
		{kind: "rcvbuf", value: 100_000},
		{kind: "sndbuf", value: 50_000},
		{kind: "timeout", value: 20_000},
	}
	if len(fake.calls) != len(expected) {
		t.Fatalf("unexpected calls %+v", fake.calls)
	}
	for index := range expected {
		if fake.calls[index] != expected[index] {
			t.Fatalf("call %d: expected %+v, got %+v", index, expected[index], fake.calls[index])
		}
	}
}

func TestApplyTCPSocketOptionsSkipsZeroLeaves(t *testing.T) {
	fake := installSocketFake(t)
	if err := applyTCPSocketOptions(7, option.TCPOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("empty options made socket calls: %+v", fake.calls)
	}
	// A zero-valued leaf is indistinguishable from an absent leaf by design.
	if err := applyTCPSocketOptions(7, option.TCPOptions{ReceiveBufferSize: 0, SendBufferSize: 0}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("zero leaves made socket calls: %+v", fake.calls)
	}
}

func TestApplyTCPSocketOptionsFailureStops(t *testing.T) {
	fake := installSocketFake(t)
	fake.setErr = E.New("EPERM")
	fake.setFailKind = "rcvbuf"
	err := applyTCPSocketOptions(7, option.TCPOptions{ReceiveBufferSize: 1, SendBufferSize: 2, UserTimeoutMillis: 3})
	if err == nil {
		t.Fatal("expected the first setsockopt error")
	}
	if len(fake.calls) != 1 {
		t.Fatalf("a failed option must stop the sequence, got %+v", fake.calls)
	}
	fake = installSocketFake(t)
	fake.timeoutErr = E.New("EINVAL")
	if err = applyTCPSocketOptions(7, option.TCPOptions{UserTimeoutMillis: 3}); err == nil {
		t.Fatal("expected the user timeout error")
	}
}

func TestEnsureAcceptedTCPSocketOptionsInheritance(t *testing.T) {
	// The listening socket value was inherited: no second setsockopt.
	fake := installSocketFake(t)
	fake.getValue = 200_000
	conn := &fakeSyscallConn{rawConn: &fakeRawConn{fd: 9}}
	if err := ensureAcceptedTCPSocketOptions(conn, option.TCPOptions{
		ReceiveBufferSize: 100_000,
		SendBufferSize:    100_000,
		UserTimeoutMillis: 5_000,
	}); err != nil {
		t.Fatal(err)
	}
	expected := []socketCall{
		{kind: "get-rcvbuf"},
		{kind: "get-sndbuf"},
		{kind: "timeout", value: 5_000},
	}
	if len(fake.calls) != len(expected) {
		t.Fatalf("unexpected calls %+v", fake.calls)
	}
	for index := range expected {
		if fake.calls[index] != expected[index] {
			t.Fatalf("call %d: expected %+v, got %+v", index, expected[index], fake.calls[index])
		}
	}
	// A missing/smaller effective value is re-applied on the accepted socket.
	fake = installSocketFake(t)
	fake.getValue = 1
	conn = &fakeSyscallConn{rawConn: &fakeRawConn{fd: 9}}
	if err := ensureAcceptedTCPSocketOptions(conn, option.TCPOptions{ReceiveBufferSize: 100_000}); err != nil {
		t.Fatal(err)
	}
	foundSet := false
	for _, call := range fake.calls {
		if call.kind == "rcvbuf" && call.value == 100_000 {
			foundSet = true
		}
	}
	if !foundSet {
		t.Fatalf("a non-inherited buffer was not re-applied: %+v", fake.calls)
	}
	// A getsockopt error is best-effort: re-apply the value.
	fake = installSocketFake(t)
	fake.getErr = E.New("ENOPROTOOPT")
	conn = &fakeSyscallConn{rawConn: &fakeRawConn{fd: 9}}
	if err := ensureAcceptedTCPSocketOptions(conn, option.TCPOptions{SendBufferSize: 4096}); err != nil {
		t.Fatal(err)
	}
	foundSet = false
	for _, call := range fake.calls {
		if call.kind == "sndbuf" && call.value == 4096 {
			foundSet = true
		}
	}
	if !foundSet {
		t.Fatalf("a failed verification was not repaired: %+v", fake.calls)
	}
}

func TestEnsureAcceptedTCPSocketOptionsRequiresNativeSocket(t *testing.T) {
	installSocketFake(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := ensureAcceptedTCPSocketOptions(client, option.TCPOptions{ReceiveBufferSize: 4096}); err == nil {
		t.Fatal("a non-native connection must be rejected")
	}
}

type fakeRawConn struct {
	fd          uintptr
	controlErr  error
	controlCall int
}

func (c *fakeRawConn) Control(f func(fd uintptr)) error {
	c.controlCall++
	if c.controlErr != nil {
		return c.controlErr
	}
	f(c.fd)
	return nil
}

func (c *fakeRawConn) Read(f func(fd uintptr) (done bool)) error {
	return errors.New("not used")
}

func (c *fakeRawConn) Write(f func(fd uintptr) (done bool)) error {
	return errors.New("not used")
}

type fakeSyscallConn struct {
	net.Conn
	rawConn syscall.RawConn
}

func (c *fakeSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return c.rawConn, nil
}

func TestTCPControlAppliesOnlyToTCP(t *testing.T) {
	fake := installSocketFake(t)
	control := TCPControl(option.TCPOptions{ReceiveBufferSize: 4096, UserTimeoutMillis: 1000})
	if control == nil {
		t.Fatal("expected a control hook")
	}
	rawConn := &fakeRawConn{fd: 5}
	if err := control("udp", "127.0.0.1:53", rawConn); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 || rawConn.controlCall != 0 {
		t.Fatalf("UDP must not receive TCP options: %+v", fake.calls)
	}
	if err := control("tcp4", "192.0.2.1:443", rawConn); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0].kind != "rcvbuf" || fake.calls[1].kind != "timeout" {
		t.Fatalf("unexpected TCP calls %+v", fake.calls)
	}
	if TCPControl(option.TCPOptions{}) != nil {
		t.Fatal("empty options must not install a control")
	}
	// A raw control failure is reported and no option is applied.
	fake = installSocketFake(t)
	rawConn = &fakeRawConn{fd: 5, controlErr: E.New("EBADF")}
	if err := control("tcp", "192.0.2.1:443", rawConn); err == nil {
		t.Fatal("expected the raw control error")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("options applied without a valid fd: %+v", fake.calls)
	}
}
