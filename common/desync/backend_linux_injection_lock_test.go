//go:build linux

package desync

import (
	"syscall"
	"testing"
	"time"
)

func TestLinuxInjectionDoesNotAcquireOwnerMutex(t *testing.T) {
	c, p := injectionFixture(t, FamilyIPv4)
	m := installInjectionModel(t, c, p)
	c.owner.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- c.inject(p) }()
	select {
	case err := <-done:
		c.owner.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		c.owner.mu.Unlock()
		<-done
		t.Fatal("raw path acquired owner/group mutex")
	}
	m.assertEvents(injectionSuccessEvents(FamilyIPv4))
}

func TestLinuxInjectionForkWriterWaitsThroughClose(t *testing.T) {
	c, p := injectionFixture(t, FamilyIPv6)
	m := installInjectionModel(t, c, p)
	m.sendEntered = make(chan struct{})
	m.sendRelease = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- c.inject(p) }()
	<-m.sendEntered
	attempting, acquired := make(chan struct{}), make(chan struct{})
	go func() {
		close(attempting)
		syscall.ForkLock.Lock()
		m.mu.Lock()
		closed := false
		for _, e := range m.events {
			if e == "close" {
				closed = true
			}
		}
		m.mu.Unlock()
		syscall.ForkLock.Unlock()
		if !closed {
			t.Error("fork writer passed before actual raw Close")
		}
		close(acquired)
	}()
	<-attempting
	select {
	case <-acquired:
		t.Error("fork writer passed active raw Sendto")
	default:
	}
	close(m.sendRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("fork writer not released")
	}
	m.assertEvents(injectionSuccessEvents(FamilyIPv6))
}
