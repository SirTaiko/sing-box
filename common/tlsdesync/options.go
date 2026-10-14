package tlsdesync

import (
	"fmt"
	"strconv"
	"strings"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

// Options is an experimental Linux/IPv4 packet strategy. It is deliberately
// separate from the upstream TLS fragmentation and spoofing options.
type Options struct {
	Mode           string `json:"mode,omitempty"`
	Split          string `json:"split,omitempty"`
	Overlap        int    `json:"overlap,omitempty"`
	OverlapPattern string `json:"overlap_pattern,omitempty"`
	FakeSNI        string `json:"fake_sni,omitempty"`
	FakeRepeats    int    `json:"fake_repeats,omitempty"`
	FakeMethod     string `json:"fake_method,omitempty"`
	FakeTTL        int    `json:"fake_ttl,omitempty"`
	SegmentDelayMS int    `json:"segment_delay_ms,omitempty"`
	pattern        []byte
}

func (o Options) Validate() error {
	if !Supported {
		return fmt.Errorf("tls_desync requires Linux")
	}
	if o.Mode != "" && o.Mode != "multisplit" && o.Mode != "multidisorder" {
		return fmt.Errorf("tls_desync: unknown mode %q", o.Mode)
	}
	if o.Overlap < 0 || o.Overlap > 4096 || o.FakeRepeats < 0 || o.FakeRepeats > 16 || o.SegmentDelayMS < 0 || o.SegmentDelayMS > 500 {
		return fmt.Errorf("tls_desync: overlap/repeats/delay outside experimental bounds")
	}
	if o.FakeTTL < 0 || o.FakeTTL > 255 || (o.FakeMethod == "ttl" && o.FakeTTL == 0) {
		return fmt.Errorf("tls_desync: invalid fake_ttl")
	}
	switch o.FakeMethod {
	case "", "wrong-sequence", "wrong-checksum", "wrong-ack", "wrong-md5", "ttl":
	default:
		return fmt.Errorf("tls_desync: unknown fake_method %q", o.FakeMethod)
	}
	if o.FakeSNI == "" && (o.Overlap > 0 || o.FakeRepeats > 0 || o.FakeMethod != "" || o.FakeTTL > 0) {
		return fmt.Errorf("tls_desync: fake_sni required for fake/overlap options")
	}
	if len(o.FakeSNI) > 253 || strings.ContainsAny(o.FakeSNI, "\x00 /:") {
		return fmt.Errorf("tls_desync: invalid fake_sni")
	}
	if o.OverlapPattern != "" && o.Overlap == 0 {
		return fmt.Errorf("tls_desync: overlap_pattern requires overlap")
	}
	for _, p := range strings.Split(o.positions(), ",") {
		if p == "midsld" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 16384 {
			return fmt.Errorf("tls_desync: invalid split position %q", p)
		}
	}
	return nil
}

func (o Options) positions() string {
	if o.Split == "" {
		return "1,midsld"
	}
	return o.Split
}

// splitPoints requires a complete ClientHello in one TLS record and ascending
// positions. It does not silently apply a partial strategy to a large hello.
func (o Options) splitPoints(b []byte) ([]int, error) {
	sni := tf.IndexTLSServerName(b)
	if sni == nil {
		return nil, fmt.Errorf("tls_desync: complete ClientHello with SNI required")
	}
	var points []int
	for _, p := range strings.Split(o.positions(), ",") {
		var n int
		if p == "midsld" {
			// The label immediately before the final dot, as in zapret's midsld.
			labels := strings.Split(sni.ServerName, ".")
			if len(labels) < 2 {
				return nil, fmt.Errorf("tls_desync: midsld requires a dotted name")
			}
			label := labels[len(labels)-2]
			n = sni.Index + len(sni.ServerName) - len(labels[len(labels)-1]) - 1 - len(label) + len(label)/2
		} else {
			n, _ = strconv.Atoi(p)
		}
		if n <= 0 || n >= len(b) || (len(points) > 0 && n <= points[len(points)-1]) {
			return nil, fmt.Errorf("tls_desync: split positions must increase inside ClientHello")
		}
		points = append(points, n)
	}
	return append(points, len(b)), nil
}
