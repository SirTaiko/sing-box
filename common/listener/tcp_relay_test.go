package listener

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestListenerTCPRelayPolicyAbsentIsEmpty(t *testing.T) {
	listener := &Listener{}
	relayOptions, err := listener.buildTCPRelayOptions()
	if err != nil {
		t.Fatal(err)
	}
	if !relayOptions.Empty() {
		t.Fatalf("absent relay policy must stay empty: %+v", relayOptions)
	}
}

func TestListenerTCPRelayPolicyPropagation(t *testing.T) {
	orphanTime := badoption.Duration(5 * time.Second)
	listener := &Listener{
		listenOptions: option.ListenOptions{
			TCPDisableSplice: true,
			TCPMaxOrphanTime: &orphanTime,
		},
	}
	relayOptions, err := listener.buildTCPRelayOptions()
	if err != nil {
		t.Fatal(err)
	}
	expected := adapter.TCPRelayOptions{
		DisableSplice:    true,
		MaxOrphanTime:    5 * time.Second,
		HasMaxOrphanTime: true,
	}
	if relayOptions != expected {
		t.Fatalf("unexpected relay policy: %+v", relayOptions)
	}
	listener.tcpRelayOptions = relayOptions

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	metadata := listener.newTCPInboundMetadata(local)
	if metadata.TCPRelayOptions != expected {
		t.Fatalf("accepted metadata lost the relay policy: %+v", metadata.TCPRelayOptions)
	}
	if metadata.Source.IsValid() {
		// net.Pipe has no meaningful source; only the policy is under test.
		t.Log("pipe source", metadata.Source)
	}
}

func TestListenerTCPRelayPolicyZeroOrphanTime(t *testing.T) {
	zero := badoption.Duration(0)
	listener := &Listener{listenOptions: option.ListenOptions{TCPMaxOrphanTime: &zero}}
	relayOptions, err := listener.buildTCPRelayOptions()
	if err != nil {
		t.Fatal(err)
	}
	if relayOptions.Empty() || !relayOptions.HasMaxOrphanTime || relayOptions.MaxOrphanTime != 0 {
		t.Fatalf("an explicit zero must be carried as configured policy: %+v", relayOptions)
	}
}

func TestListenerTCPRelayPolicyNegativeRejected(t *testing.T) {
	negative := badoption.Duration(-time.Second)
	listener := &Listener{listenOptions: option.ListenOptions{TCPMaxOrphanTime: &negative}}
	if _, err := listener.buildTCPRelayOptions(); err == nil {
		t.Fatal("a negative orphan time must be rejected by the listener owner")
	}
}

func TestListenerTCPRelayPolicySurvivesDetourMetadata(t *testing.T) {
	orphanTime := badoption.Duration(3 * time.Second)
	listener := &Listener{
		listenOptions: option.ListenOptions{
			Detour:           "detour-inbound",
			TCPDisableSplice: true,
			TCPMaxOrphanTime: &orphanTime,
		},
	}
	relayOptions, err := listener.buildTCPRelayOptions()
	if err != nil {
		t.Fatal(err)
	}
	listener.tcpRelayOptions = relayOptions
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	metadata := listener.newTCPInboundMetadata(local)
	//nolint:staticcheck
	if metadata.InboundDetour != "detour-inbound" {
		t.Fatalf("detour field lost: %+v", metadata)
	}
	if metadata.TCPRelayOptions != relayOptions {
		t.Fatalf("detour metadata lost the origin relay policy: %+v", metadata.TCPRelayOptions)
	}
}

var _ = E.New
