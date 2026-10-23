package option

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

func TestTCPRelayPolicyAbsent(t *testing.T) {
	policy, err := (ListenOptions{}).TCPRelayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Empty() {
		t.Fatalf("absent relay options must stay empty: %+v", policy)
	}
	if policy.HasMaxOrphanTime || policy.DisableSplice {
		t.Fatalf("absent relay options must not configure policy: %+v", policy)
	}
}

func TestTCPRelayPolicyDisableSplice(t *testing.T) {
	policy, err := (ListenOptions{TCPDisableSplice: true}).TCPRelayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Empty() || !policy.DisableSplice || policy.HasMaxOrphanTime {
		t.Fatalf("unexpected disable splice policy: %+v", policy)
	}
}

func TestTCPRelayPolicyOrphanTime(t *testing.T) {
	zero := badoption.Duration(0)
	policy, err := (ListenOptions{TCPMaxOrphanTime: &zero}).TCPRelayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Empty() || !policy.HasMaxOrphanTime || policy.MaxOrphanTime != 0 {
		t.Fatalf("an explicit zero must configure the orphan policy without a timer: %+v", policy)
	}
	five := badoption.Duration(5 * time.Second)
	policy, err = (ListenOptions{TCPMaxOrphanTime: &five}).TCPRelayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !policy.HasMaxOrphanTime || policy.MaxOrphanTime != 5*time.Second {
		t.Fatalf("unexpected orphan time: %+v", policy)
	}
}

func TestTCPRelayPolicyNegativeOrphanTime(t *testing.T) {
	negative := badoption.Duration(-time.Second)
	if _, err := (ListenOptions{TCPMaxOrphanTime: &negative}).TCPRelayPolicy(); err == nil {
		t.Fatal("a negative orphan time must be rejected")
	}
}

func TestTCPRelayOptionsSchemaFields(t *testing.T) {
	var options ListenOptions
	err := json.Unmarshal([]byte(`{"listen_port":1080,"tcp_disable_splice":true,"tcp_max_orphan_time":"5s"}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	if !options.TCPDisableSplice {
		t.Fatal("tcp_disable_splice was not parsed")
	}
	if options.TCPMaxOrphanTime == nil || time.Duration(*options.TCPMaxOrphanTime) != 5*time.Second {
		t.Fatalf("tcp_max_orphan_time was not parsed: %+v", options.TCPMaxOrphanTime)
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip map[string]any
	if err = json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip["tcp_disable_splice"] != true {
		t.Fatalf("tcp_disable_splice missing from encoded options: %s", encoded)
	}
	if _, loaded := roundTrip["tcp_max_orphan_time"]; !loaded {
		t.Fatalf("tcp_max_orphan_time missing from encoded options: %s", encoded)
	}

	// An absent policy must not appear in the encoded object.
	encoded, err = json.Marshal(ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("absent relay fields must stay absent: %s", encoded)
	}
}

func TestTCPRelayListenOptionsStaysComparable(t *testing.T) {
	// Existing inbound option equality checks require ListenOptions to stay
	// comparable; both new fields are scalar or pointer values.
	first := ListenOptions{TCPDisableSplice: true}
	second := first
	if first != second {
		t.Fatal("copied listen options must compare equal")
	}
	if first == (ListenOptions{}) {
		t.Fatal("tcp_disable_splice must change the option value")
	}
	five := badoption.Duration(5 * time.Second)
	withOrphan := ListenOptions{TCPMaxOrphanTime: &five}
	if withOrphan == (ListenOptions{}) {
		t.Fatal("tcp_max_orphan_time must change the option value")
	}
}
