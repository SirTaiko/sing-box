//go:build linux

package desync

import (
	"errors"
	"syscall"
	"testing"
)

// retainedRawConn is a memory-only syscall.RawConn. Only Control is used by the
// Linux sender factory; Read/Write are never reached without a real socket.
type retainedRawConn struct{}

func (retainedRawConn) Control(f func(fd uintptr)) error {
	f(0)
	return nil
}

func (retainedRawConn) Read(func(fd uintptr) (done bool)) error {
	return errors.New("retained test raw conn: read is not used")
}

func (retainedRawConn) Write(func(fd uintptr) (done bool)) error {
	return errors.New("retained test raw conn: write is not used")
}

// retainedSyscallConn exposes a RawConn so the platform factory reaches the
// native-source contract without a real socket.
type retainedSyscallConn struct {
	*retainedFakeConn
	holder *retainedHolder
}

func (c *retainedSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return retainedRawConn{}, nil
}

func (c *retainedSyscallConn) AcquireNativeHold() (func(), error) {
	return c.holder.AcquireNativeHold()
}

// R07/R15: the Linux factory acquires its construction reference before the
// native source is inspected and releases it once the sender exists. A refused
// acquisition starts no native work.
func TestLinuxPlatformSenderConstructsUnderAdmission(t *testing.T) {
	holder := &retainedHolder{}
	conn := &retainedSyscallConn{retainedFakeConn: &retainedFakeConn{}, holder: holder}
	sender, err := newPlatformStreamNative().NewSender(conn, nil)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	if sender == nil {
		t.Fatalf("NewSender returned no sender")
	}
	acquired, released := holder.counts()
	if acquired != 1 || released != 1 {
		t.Fatalf("factory construction acquired=%d released=%d, want one temporary reference", acquired, released)
	}
}

// R15: without an admission owner the factory refuses before inspecting the
// native source.
func TestLinuxPlatformSenderRequiresAdmission(t *testing.T) {
	plain := &retainedFakeConn{}
	if _, err := newPlatformStreamNative().NewSender(plain, nil); err == nil {
		t.Fatalf("NewSender accepted a connection without an admission owner")
	}
}

// R08/R09: a refused admission refuses the submission without a fallback write.
func TestLinuxPlatformSenderRefusedAdmissionHasNoSend(t *testing.T) {
	holder := &retainedHolder{refuse: admissionRefused(errLeaseClosed)}
	conn := &retainedSyscallConn{retainedFakeConn: &retainedFakeConn{}, holder: holder}
	sender, err := newPlatformStreamNative().NewSender(conn, nil)
	if err == nil {
		t.Fatalf("NewSender accepted a refusing admission holder: %v", sender)
	}
	if !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("NewSender error = %v, want admission refusal", err)
	}
}
