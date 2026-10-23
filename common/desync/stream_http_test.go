package desync

import (
	"bytes"
	"strings"
	"testing"
)

// Source mapping: tpws tamper.c tamper_out HTTP branch (zapret v72.9
// c849e55e). Every oracle below is the intentional representation change the
// pinned source produces, not a byte-exact pass-through.

const httpFixture = "GET / HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY"

func tamperHTTP(t *testing.T, spec *httpTamperSpec, request string) string {
	t.Helper()
	block := make([]byte, len(request), streamBlockCapacity)
	copy(block, request)
	block, err := applyHTTPTamper(block, spec, &streamRandom{source: strings.NewReader(strings.Repeat("\x00", 4096))})
	if err != nil {
		t.Fatalf("applyHTTPTamper: %v", err)
	}
	return string(block)
}

func TestHTTPTamperGolden(t *testing.T) {
	tests := []struct {
		name string
		spec *httpTamperSpec
		want string
	}{
		{
			// --hostcase rewrites the header name to the default "host".
			name: "hostcase default",
			spec: &httpTamperSpec{hostCase: true, hostSpell: [4]byte{'h', 'o', 's', 't'}},
			want: "GET / HTTP/1.1\r\nhost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --hostspell sets the exact 4-byte spelling and implies hostcase.
			name: "hostspell custom",
			spec: &httpTamperSpec{hostCase: true, hostSpell: [4]byte{'H', 'o', 'S', 't'}},
			want: "GET / HTTP/1.1\r\nHoSt: Example.COM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --hostdot inserts one dot at the end of the value (before CR).
			name: "hostdot",
			spec: &httpTamperSpec{hostDot: true},
			want: "GET / HTTP/1.1\r\nHost: Example.COM.\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --hosttab inserts one literal tab at the same anchor.
			name: "hosttab",
			spec: &httpTamperSpec{hostTab: true},
			want: "GET / HTTP/1.1\r\nHost: Example.COM\t\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --hostnospace removes exactly the single space after Host:.
			name: "hostnospace",
			spec: &httpTamperSpec{hostNoSpace: true},
			want: "GET / HTTP/1.1\r\nHost:Example.COM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --domcase alternates over the value including the leading space
			// (tamper.c starts at pHost+5 and uses pointer parity; the block
			// offset is the deterministic equivalent).
			name: "domcase",
			spec: &httpTamperSpec{domCase: true},
			want: "GET / HTTP/1.1\r\nHost: ExAmPlE.CoM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --methodspace inserts an extra space after the method anchor.
			name: "methodspace",
			spec: &httpTamperSpec{methodSpace: true},
			want: "GET  / HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --methodeol inserts CRLF before the method.
			name: "methodeol",
			spec: &httpTamperSpec{methodEOL: true},
			want: "\r\nGET / HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY",
		},
		{
			// --methodeol --unixeol inserts a single LF before the method.
			name: "methodeol unixeol",
			spec: &httpTamperSpec{methodEOL: true, unixEOL: true},
			want: "\nGET / HTTP/1.1\nHost: Example.COM\nUser-Agent: test\n\nBODY",
		},
		{
			// --unixeol replaces CRLF up to and including the end of headers.
			name: "unixeol",
			spec: &httpTamperSpec{unixEOL: true},
			want: "GET / HTTP/1.1\nHost: Example.COM\nUser-Agent: test\n\nBODY",
		},
		{
			// Source order from tamper.c: methodspace, hostdot, hostnospace,
			// hostcase.
			name: "combined order",
			spec: &httpTamperSpec{
				methodSpace: true, hostDot: true, hostNoSpace: true,
				hostCase: true, hostSpell: [4]byte{'h', 'o', 's', 't'},
			},
			want: "GET  / HTTP/1.1\r\nhost:Example.COM.\r\nUser-Agent: test\r\n\r\nBODY",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := tamperHTTP(t, test.spec, httpFixture)
			if got != test.want {
				t.Fatalf("got  %q\nwant %q", got, test.want)
			}
		})
	}
}

// TestHTTPHostLookalikeIsNotTouched is a non-vacuous negative control for the
// Host anchor: a naive strings.Replace("Host:", "host:") mutant would rewrite
// X-Host, but tpws requires LF + Host:.
func TestHTTPHostLookalikeIsNotTouched(t *testing.T) {
	request := "GET / HTTP/1.1\r\nX-Host: Example.COM\r\nProxy-Host: x\r\n\r\n"
	got := tamperHTTP(t, &httpTamperSpec{hostCase: true, hostSpell: [4]byte{'h', 'o', 's', 't'}}, request)
	if got != request {
		t.Fatalf("lookalike header was rewritten: %q", got)
	}
}

func TestHTTPHostPadGolden(t *testing.T) {
	// hsize is 9 for CRLF. A zero random source yields letter 'a' and value
	// 0x0000, so one dummy header is exactly "a0000: " + pad + CRLF.
	spec := &httpTamperSpec{hostPad: 9}
	got := tamperHTTP(t, spec, httpFixture)
	want := "GET / HTTP/1.1\r\na0000: \r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY"
	if got != want {
		t.Fatalf("hostpad=9 got %q want %q", got, want)
	}

	spec = &httpTamperSpec{hostPad: 20}
	got = tamperHTTP(t, spec, httpFixture)
	want = "GET / HTTP/1.1\r\na0000: aaaaaaaaaaa\r\nHost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY"
	if got != want {
		t.Fatalf("hostpad=20 got %q want %q", got, want)
	}
}

func TestHTTPUnixEOLStopsAtHeaderEnd(t *testing.T) {
	request := "POST /x HTTP/1.0\r\nHost: a.example\r\n\r\nBODY\r\nKEEP\r\n"
	spec := &httpTamperSpec{unixEOL: true}
	got := tamperHTTP(t, spec, request)
	want := "POST /x HTTP/1.0\nHost: a.example\n\nBODY\r\nKEEP\r\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestHTTPMethodlessDataIsNotTampered(t *testing.T) {
	payload := "hello Host: Example.COM\r\n\r\n"
	got := tamperHTTP(t, &httpTamperSpec{hostCase: true, hostSpell: [4]byte{'h', 'o', 's', 't'}}, payload)
	if got != payload {
		t.Fatalf("non-request block changed: %q", got)
	}
}

func TestHTTPFindHostHeader(t *testing.T) {
	if findHostHeader([]byte("GET / HTTP/1.1\r\nHost: x\r\n")) != 16 {
		t.Fatal("Host header offset mismatch")
	}
	if findHostHeader([]byte("Host: x\r\n")) != -1 {
		t.Fatal("header without a preceding LF must not match")
	}
	if findHostHeader([]byte("GET / HTTP/1.1\r\nhost:\tx\r\n")) != 16 {
		t.Fatal("case-insensitive Host must match")
	}
}

func TestHTTPBlockFactsAnchors(t *testing.T) {
	block := []byte("GET / HTTP/1.1\r\nHost: www.example.org\r\nUser-Agent: x\r\n\r\n")
	set := streamBlockFacts(ProtocolHTTP, block)
	if !set.HostKnown || set.Host != "www.example.org" {
		t.Fatalf("host=%q known=%v", set.Host, set.HostKnown)
	}
	if string(block[set.HostStart:set.HostEnd]) != "www.example.org" {
		t.Fatalf("host anchors %d:%d", set.HostStart, set.HostEnd)
	}
	if !set.methodOK || set.MethodStart != 0 {
		t.Fatalf("method anchors ok=%v start=%d", set.methodOK, set.MethodStart)
	}
	if got := string(block[set.SLDStart:set.SLDEnd]); got != "example" {
		t.Fatalf("SLD anchors = %q", got)
	}
}

func TestFindNLD(t *testing.T) {
	start, end, ok := findNLD([]byte("www.example.org"), 2)
	if !ok || "www.example.org"[start:end] != "example" {
		t.Fatalf("SLD = %d:%d %v", start, end, ok)
	}
	if _, _, ok = findNLD([]byte("localhost"), 2); ok {
		t.Fatal("single-label host has no second-level domain")
	}
	start, end, ok = findNLD([]byte("x.com"), 2)
	if !ok || "x.com"[start:end] != "x" {
		t.Fatalf("one-letter SLD = %d:%d %v", start, end, ok)
	}
}

func TestHTTPTamperRespectsCapacity(t *testing.T) {
	block := make([]byte, len(httpFixture), len(httpFixture))
	copy(block, httpFixture)
	if _, err := applyHTTPTamper(block, &httpTamperSpec{methodSpace: true}, &streamRandom{source: bytes.NewReader(nil)}); err != nil {
		t.Fatalf("capacity-limited tamper failed: %v", err)
	}
	if !bytes.Equal(block, []byte(httpFixture)) {
		t.Fatal("insertion without spare capacity must be dropped, not truncated")
	}
}
