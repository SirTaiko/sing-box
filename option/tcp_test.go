package option

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

func addrPointer(value string) *badoption.Addr {
	addr := badoption.Addr(netipMustParseAddr(value))
	return &addr
}

func netipMustParseAddr(value string) netip.Addr {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		panic(err)
	}
	return addr
}

func durationDuration(value time.Duration) badoption.Duration {
	return badoption.Duration(value)
}

func unmarshalStrict(content []byte, value any) error {
	return singjson.UnmarshalDisallowUnknownFields(content, value)
}

func boolUint32(value uint32) *uint32 {
	return &value
}

func boolDuration(value time.Duration) *badoption.Duration {
	parsed := badoption.Duration(value)
	return &parsed
}

func TestTCPSocketOptionsAbsentKeepsPreviousBehavior(t *testing.T) {
	var options TCPSocketOptions
	built, err := options.BuildForPlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	if !built.Empty() {
		t.Fatalf("absent options must be empty, got %+v", built)
	}
	zero := TCPSocketOptions{
		ReceiveBufferSize: boolUint32(0),
		SendBufferSize:    boolUint32(0),
		UserTimeout:       boolDuration(0),
	}
	built, err = zero.BuildForPlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	if !built.Empty() {
		t.Fatalf("explicit zero must mean no override, got %+v", built)
	}
}

func TestTCPSocketOptionsLinuxHalving(t *testing.T) {
	options := TCPSocketOptions{
		ReceiveBufferSize: boolUint32(1_000_000),
		SendBufferSize:    boolUint32(500_001),
		UserTimeout:       boolDuration(20 * time.Second),
	}
	built, err := options.BuildForPlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	if built.ReceiveBufferSize != 500_000 {
		t.Fatalf("receive buffer not halved: %d", built.ReceiveBufferSize)
	}
	if built.SendBufferSize != 250_000 {
		t.Fatalf("send buffer not halved: %d", built.SendBufferSize)
	}
	if built.UserTimeoutMillis != 20_000 {
		t.Fatalf("user timeout milliseconds: %d", built.UserTimeoutMillis)
	}
	odd := TCPSocketOptions{ReceiveBufferSize: boolUint32(1)}
	built, err = odd.BuildForPlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	if built.ReceiveBufferSize != 0 {
		t.Fatalf("a value of 1 halves to zero and makes no call, got %d", built.ReceiveBufferSize)
	}
}

func TestTCPSocketOptionsOtherPlatformDirectBytes(t *testing.T) {
	options := TCPSocketOptions{
		ReceiveBufferSize: boolUint32(1_000_000),
		SendBufferSize:    boolUint32(500_001),
	}
	built, err := options.BuildForPlatform(false)
	if err != nil {
		t.Fatal(err)
	}
	if built.ReceiveBufferSize != 1_000_000 || built.SendBufferSize != 500_001 {
		t.Fatalf("non-Linux buffers must be passed directly: %+v", built)
	}
}

func TestTCPSocketOptionsRejectsInvalidValues(t *testing.T) {
	cases := []TCPSocketOptions{
		{ReceiveBufferSize: boolUint32(math.MaxInt32 + 1)},
		{SendBufferSize: boolUint32(math.MaxInt32 + 1)},
		{UserTimeout: boolDuration(-time.Second)},
		{UserTimeout: boolDuration(1500 * time.Microsecond)},
		{UserTimeout: boolDuration(time.Duration(math.MaxInt32+1) * time.Millisecond)},
	}
	for index, options := range cases {
		if _, err := options.BuildForPlatform(true); err == nil {
			t.Fatalf("case %d: expected an error", index)
		}
	}
	// The largest accepted values are exactly representable.
	accepted := TCPSocketOptions{
		ReceiveBufferSize: boolUint32(math.MaxInt32),
		UserTimeout:       boolDuration(time.Duration(math.MaxInt32) * time.Millisecond),
	}
	if _, err := accepted.BuildForPlatform(true); err != nil {
		t.Fatalf("max accepted values rejected: %v", err)
	}
}

func TestTCPSocketOptionsUserTimeoutWindowsInapplicable(t *testing.T) {
	options := TCPSocketOptions{UserTimeout: boolDuration(time.Second)}
	if _, err := options.BuildForPlatform(false); err == nil {
		t.Fatal("a positive user timeout must be an explicit error off Linux")
	}
	// Buffers remain valid off Linux.
	if _, err := (TCPSocketOptions{ReceiveBufferSize: boolUint32(4096)}).BuildForPlatform(false); err != nil {
		t.Fatal(err)
	}
}

func TestTCPSocketOptionsStrictJSON(t *testing.T) {
	content := []byte(`{"receive_buffer_size":1048576,"send_buffer_size":65536,"user_timeout":"20s"}`)
	var options TCPSocketOptions
	if err := json.Unmarshal(content, &options); err != nil {
		t.Fatal(err)
	}
	built, err := options.BuildForPlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	if built.ReceiveBufferSize != 524288 || built.SendBufferSize != 32768 || built.UserTimeoutMillis != 20000 {
		t.Fatalf("unexpected built options %+v", built)
	}
	var unknown TCPSocketOptions
	if err := unmarshalStrict([]byte(`{"byte_range":1}`), &unknown); err == nil {
		t.Fatal("unknown leaf must be rejected")
	}
}

func bindingPointer(bindings []TCPListenBinding) *TCPListenBindingList {
	list := TCPListenBindingList(bindings)
	return &list
}

func TestTCPListenBindingValidation(t *testing.T) {
	valid := []TCPListenBinding{
		{Address: addrPointer("192.0.2.1"), IPVersion: 4},
		{Address: addrPointer("2001:db8::1"), Interface: "eth0"},
		{Interface: "eth0", IPVersion: 4},
		{Interface: "eth0", IPVersion: 6},
		{IPVersion: 6, LinkLocal: TCPListenLinkLocalPrefer},
		{Address: addrPointer("fe80::1%eth0"), LinkLocal: TCPListenLinkLocalUnwanted},
	}
	if err := ValidateTCPListenBindings(valid); err != nil {
		t.Fatalf("valid bindings rejected: %v", err)
	}
	invalid := [][]TCPListenBinding{
		{{Interface: "eth0"}},
		{{IPVersion: 6}},
		{{IPVersion: 4, LinkLocal: TCPListenLinkLocalPrefer}},
		{{Interface: "eth0", IPVersion: 5}},
		{{Address: addrPointer("192.0.2.1"), IPVersion: 6}},
		{{Interface: "eth0", IPVersion: 4, WaitIfUp: durationDuration(time.Second), WaitIPLinkLocal: durationDuration(time.Second)}},
		{{Interface: "eth0", IPVersion: 6, WaitIPLinkLocal: durationDuration(time.Second), LinkLocal: TCPListenLinkLocalForce}},
		{{Interface: "eth0", IPVersion: 4, WaitIP: -durationDuration(time.Second)}},
		{{Address: addrPointer("192.0.2.1"), IPVersion: 4}, {Address: addrPointer("192.0.2.1"), IPVersion: 4}},
	}
	for index, bindings := range invalid {
		if err := ValidateTCPListenBindings(bindings); err == nil {
			t.Fatalf("invalid case %d accepted: %+v", index, bindings)
		}
	}
	// wait_ifup without an interface is rejected above but wait_ifup with one
	// is valid; make that explicit.
	if err := ValidateTCPListenBindings([]TCPListenBinding{{Interface: "eth0", IPVersion: 4, WaitIfUp: durationDuration(time.Second)}}); err != nil {
		t.Fatalf("wait_ifup with interface rejected: %v", err)
	}
	tooMany := make([]TCPListenBinding, 33)
	for index := range tooMany {
		tooMany[index] = TCPListenBinding{Address: addrPointer(fmt.Sprintf("192.0.2.%d", index+1)), IPVersion: 4}
	}
	if err := ValidateTCPListenBindings(tooMany); err == nil {
		t.Fatal("33 bindings must exceed the source limit")
	}
}

func TestTCPListenBindingStrictJSON(t *testing.T) {
	content := []byte(`{"bindings":[{"address":"2001:db8::1","interface":"eth0","ip_version":6,"link_local":"prefer","wait_ifup":"1s","wait_ip":"5s","wait_ip_linklocal":"2s"}]}`)
	var document struct {
		Bindings []TCPListenBinding `json:"bindings"`
	}
	if err := unmarshalStrict(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Bindings) != 1 {
		t.Fatalf("unexpected bindings %+v", document.Bindings)
	}
	binding := document.Bindings[0]
	if binding.LinkLocal != TCPListenLinkLocalPrefer || time.Duration(binding.WaitIP) != 5*time.Second {
		t.Fatalf("unexpected binding %+v", binding)
	}
	var unknown struct {
		Bindings []TCPListenBinding `json:"bindings"`
	}
	if err := unmarshalStrict([]byte(`{"bindings":[{"address":"192.0.2.1","wait_route":"1s"}]}`), &unknown); err == nil {
		t.Fatal("unknown binding field must be rejected")
	}
	if err := unmarshalStrict([]byte(`{"bindings":[{"address":"192.0.2.1","link_local":"allow"}]}`), &unknown); err == nil {
		t.Fatal("unknown link_local enum must be rejected")
	}
}

func TestListenOptionsStaysComparable(t *testing.T) {
	// Existing inbound option equality checks require ListenOptions to stay
	// comparable; tcp_listen_bindings is therefore a pointer to its list.
	if (ListenOptions{}) != (ListenOptions{}) {
		t.Fatal("zero listen options must compare equal")
	}
	first := ListenOptions{TCPListenBindings: bindingPointer([]TCPListenBinding{{Address: addrPointer("192.0.2.1")}})}
	second := first
	if first != second {
		t.Fatal("copied listen options must compare equal")
	}
	if first == (ListenOptions{}) {
		t.Fatal("a configured binding list must change the option value")
	}
}

func TestTCPListenBindingLinkLocalJSONRoundTrip(t *testing.T) {
	for _, value := range []TCPListenLinkLocal{"", TCPListenLinkLocalUnwanted, TCPListenLinkLocalNo, TCPListenLinkLocalPrefer, TCPListenLinkLocalForce} {
		content, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded TCPListenLinkLocal
		if err = json.Unmarshal(content, &decoded); err != nil {
			t.Fatal(err)
		}
		built, err := decoded.Build()
		if err != nil {
			t.Fatal(err)
		}
		if built == "" {
			t.Fatalf("decoded enum must be explicit, got %q", built)
		}
	}
}
