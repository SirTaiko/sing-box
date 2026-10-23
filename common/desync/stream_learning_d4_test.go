package desync

// D4 stream cache-learning / tamper_in tests. They exercise the actual
// connection wrapper, the engine-owned ip cache and the engine-owned learner;
// no socket, network, native or privileged operation is involved.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

const (
	d4RedirectReply = "HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\n\r\n"
	d4SuccessReply  = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	d4LocalRedirect = "HTTP/1.1 302 Found\r\nLocation: http://www.example.com/x\r\n\r\n"
	d4Request       = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
)

func d4Int(value int) *int { return &value }

func d4Rule(learning *option.DirectDesyncRuleLearning) option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{Name: "learn", Learning: learning}
}

func d4Engine(t *testing.T, rules []option.DirectDesyncStreamRule, options *option.DirectDesyncOptions) *Engine {
	t.Helper()
	if options == nil {
		options = &option.DirectDesyncOptions{}
	}
	engine, err := NewStateEngine(options, rules)
	if err != nil {
		t.Fatalf("NewStateEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// d4Connection writes one request through a fresh wrapper so the learning
// applicability and rule selection run exactly like a new tpws connection.
func d4Connection(t *testing.T, config *StreamConfig, reply string) (*fakeConn, net.Conn) {
	t.Helper()
	conn := newFakeConn()
	if reply != "" {
		conn.readBuffer.WriteString(reply)
	}
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte(d4Request)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return conn, wrapped
}

func d4ReadAll(t *testing.T, wrapped net.Conn, want string) {
	t.Helper()
	buffer := make([]byte, 4096)
	n, err := wrapped.Read(buffer)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buffer[:n]); got != want {
		t.Fatalf("Read returned %q, want the exact reply %q", got, want)
	}
}

func TestD4StreamLearningCountsRedirects(t *testing.T) {
	learning := &option.DirectDesyncRuleLearning{FailThreshold: d4Int(2)}
	rules := []option.DirectDesyncStreamRule{d4Rule(learning)}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}

	_, first := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, first, d4RedirectReply)
	if learned := engine.LearnedHosts(); len(learned) != 0 {
		t.Fatalf("learned after one failure = %v, want none before the threshold", learned)
	}

	_, second := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, second, d4RedirectReply)
	learned := engine.LearnedHosts()
	if len(learned) != 1 || learned[0] != "example.com" {
		t.Fatalf("learned = %v, want [example.com] after the second DPI redirect", learned)
	}
}

func TestD4StreamLearningSuccessResetsFailCounter(t *testing.T) {
	learning := &option.DirectDesyncRuleLearning{FailThreshold: d4Int(2)}
	rules := []option.DirectDesyncStreamRule{d4Rule(learning)}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	for _, reply := range []string{d4RedirectReply, d4SuccessReply, d4RedirectReply} {
		_, wrapped := d4Connection(t, config, reply)
		d4ReadAll(t, wrapped, reply)
	}
	if learned := engine.LearnedHosts(); len(learned) != 0 {
		t.Fatalf("learned = %v, want none because the success reset the counter", learned)
	}
	// An in-domain redirect is not a DPI redirect: it resets, it never fails.
	_, inDomain := d4Connection(t, config, d4LocalRedirect)
	d4ReadAll(t, inDomain, d4LocalRedirect)
	_, again := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, again, d4RedirectReply)
	if learned := engine.LearnedHosts(); len(learned) != 0 {
		t.Fatalf("learned = %v, want none after an in-domain redirect reset", learned)
	}
}

func TestD4StreamLearningReadFailureCounts(t *testing.T) {
	learning := &option.DirectDesyncRuleLearning{FailThreshold: d4Int(1)}
	rules := []option.DirectDesyncStreamRule{d4Rule(learning)}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	_, wrapped := d4Connection(t, config, "")
	if _, err := wrapped.Read(make([]byte, 8)); err != io.EOF {
		t.Fatalf("Read error = %v, want EOF", err)
	}
	learned := engine.LearnedHosts()
	if len(learned) != 1 || learned[0] != "example.com" {
		t.Fatalf("learned = %v, want [example.com] after a pre-reply read failure", learned)
	}
}

func TestD4StreamLearningNonHTTPReplyResets(t *testing.T) {
	learning := &option.DirectDesyncRuleLearning{FailThreshold: d4Int(2)}
	rules := []option.DirectDesyncStreamRule{d4Rule(learning)}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	_, first := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, first, d4RedirectReply)
	unknown := "\x00\x01binary-server-greeting"
	_, second := d4Connection(t, config, unknown)
	d4ReadAll(t, second, unknown)
	_, third := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, third, d4RedirectReply)
	if learned := engine.LearnedHosts(); len(learned) != 0 {
		t.Fatalf("learned = %v, want none because the unknown reply reset the counter", learned)
	}
}

func TestD4StreamLearningIgnoresRetransThreshold(t *testing.T) {
	// tpws has no TCP retransmission learning for a stream rule: the shared
	// typed retrans_threshold compiles but has no effect. One reply event at
	// fail_threshold=1 learns regardless of retrans_threshold.
	learning := &option.DirectDesyncRuleLearning{FailThreshold: d4Int(1), RetransThreshold: d4Int(10)}
	rules := []option.DirectDesyncStreamRule{d4Rule(learning)}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	if config.rules[0].learning == nil || config.rules[0].learning.retransThreshold != 10 {
		t.Fatalf("retrans_threshold was not compiled: %+v", config.rules[0].learning)
	}
	_, wrapped := d4Connection(t, config, d4RedirectReply)
	d4ReadAll(t, wrapped, d4RedirectReply)
	if learned := engine.LearnedHosts(); len(learned) != 1 {
		t.Fatalf("learned = %v, want one host after one reply event", learned)
	}
}

func TestD4PreconnectCachedHostSelectsRule(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.7")
	options := &option.DirectDesyncOptions{IPCache: &option.DirectDesyncIPCache{Hostname: true}}
	engine := d4Engine(t, nil, options)
	if !engine.ipcache.learnHost(address, "eth0", "cached.example") {
		t.Fatal("ip cache rejected the host entry")
	}
	rules := []option.DirectDesyncStreamRule{{
		Name: "cached",
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: []string{"cached.example"},
		},
		MSS: 1200,
	}}
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	recorder := &nativeRecorder{}
	config.native = recorder
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Destination: address, Port: 443}
	if err := config.PrepareSocket(context.Background(), 7, facts); err != nil {
		t.Fatal(err)
	}
	if len(recorder.prepared) != 1 || recorder.prepared[0].config.mss != 1200 {
		t.Fatalf("preconnect controls = %+v, want one MSS=1200 record from the cached host", recorder.prepared)
	}

	// Control: without the cache entry the domain rule cannot be selected
	// before connect, so no preconnect control is applied.
	control := mustCompileStream(t, rules...)
	controlEngine := d4Engine(t, nil, options)
	if err := control.AttachEngine(controlEngine); err != nil {
		t.Fatal(err)
	}
	controlRecorder := &nativeRecorder{}
	control.native = controlRecorder
	if err := control.PrepareSocket(context.Background(), 7, facts); err != nil {
		t.Fatal(err)
	}
	if len(controlRecorder.prepared) != 0 {
		t.Fatalf("preconnect controls without a cached host = %+v, want none", controlRecorder.prepared)
	}
}

func TestD4ProvisionalCachedHostIsReconsidered(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.9")
	options := &option.DirectDesyncOptions{IPCache: &option.DirectDesyncIPCache{Hostname: true}}
	engine := d4Engine(t, nil, options)
	if !engine.ipcache.learnHost(address, "eth0", "cached.example") {
		t.Fatal("ip cache rejected the host entry")
	}
	rules := []option.DirectDesyncStreamRule{
		{
			Name: "cached",
			DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
				Domain: []string{"cached.example"},
			},
			Methods:    []string{"http_tamper"},
			HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostDot: true},
		},
		{
			Name: "revealed",
			DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
				Domain: []string{"revealed.example"},
			},
			Methods:    []string{"http_tamper"},
			HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostTab: true},
		},
	}
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	conn := newFakeConn()
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Destination: address, Port: 80}
	wrapped := wrapStream(t, config, conn, facts)
	if _, err := wrapped.Write([]byte("GET / HTTP/1.1\r\nHost: revealed.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	written := conn.collected()
	if !containsBytes(written, []byte("revealed.example\t")) {
		t.Fatalf("written = %q, want the revealed-host rule (hosttab) to win over the cached rule", written)
	}
	if containsBytes(written, []byte("revealed.example.")) {
		t.Fatalf("written = %q: the provisional cached rule must not survive a revealed hostname", written)
	}
}

func TestD4StateEngineIsCaptureFree(t *testing.T) {
	rules := []option.DirectDesyncStreamRule{d4Rule(&option.DirectDesyncRuleLearning{})}
	engine := d4Engine(t, rules, nil)
	if engine.BackendName() != "state-only" {
		t.Fatalf("backend = %q, want state-only", engine.BackendName())
	}
	if !engine.LearningEnabled() {
		t.Fatal("a stream rule with learning must enable the engine learner")
	}
	other := d4Engine(t, nil, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	if err := config.AttachEngine(other); err == nil {
		t.Fatal("attaching a stream config to a second engine must be refused")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if string(haystack[index:index+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// TestD4StreamReloadIsTransactional pins the reload contract: a successful
// reload publishes a fully compiled stream snapshot, and a failed stream list
// read keeps the last-good stream rules instead of publishing a partial set.
func TestD4StreamReloadIsTransactional(t *testing.T) {
	directory := t.TempDir()
	listPath := filepath.Join(directory, "domains.txt")
	if err := os.WriteFile(listPath, []byte("one.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := []option.DirectDesyncStreamRule{{
		Name:                    "list",
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{DomainFile: []string{listPath}},
		MSS:                     1200,
	}}
	engine := d4Engine(t, rules, nil)
	config := mustCompileStream(t, rules...)
	if err := config.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	selects := func(host string) bool {
		return config.selectRule(MatchFacts{Transport: TransportTCP, Family: FamilyIPv4, Host: host, HostKnown: true}) != nil
	}
	if !selects("one.example") || selects("two.example") {
		t.Fatal("initial stream snapshot does not match the list file")
	}

	if err := os.WriteFile(listPath, []byte("two.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.ReloadLists(); err != nil {
		t.Fatalf("ReloadLists: %v", err)
	}
	if selects("one.example") || !selects("two.example") {
		t.Fatal("successful reload did not publish the new stream snapshot")
	}

	// A directory at the list path makes the stream compile fail. Nothing may
	// be published: the last-good stream snapshot must stay active.
	if err := os.Remove(listPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(listPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := engine.ReloadLists(); err == nil {
		t.Fatal("a failed stream list read must be an error")
	}
	if selects("one.example") || !selects("two.example") {
		t.Fatal("failed reload replaced the last-good stream snapshot")
	}
}
