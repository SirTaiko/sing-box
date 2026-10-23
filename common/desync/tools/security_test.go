package tools

// Hermetic bounded probes adapted from security task t_cd90c243. No DNS or
// subprocesses. The O1 stalled-pipe observation is deliberately not imported as
// a test: an arbitrary io.Reader is not preemptible, so a blocked read is a
// documented streaming-interface boundary, not a defect this test can fix.
// O2: explicit exclusion files are regular-file-only; see openExclude.
import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestSecurityDNSBoundedControls(t *testing.T) {
	// Header-count amplification is capped by 16-bit count, and invalid inputs
	// must not return partially extracted addresses.
	for _, counts := range [][2]uint16{{65535, 0}, {0, 65535}} {
		b := make([]byte, 12)
		b[2] = 0x80
		binary.BigEndian.PutUint16(b[4:6], counts[0])
		binary.BigEndian.PutUint16(b[6:8], counts[1])
		got, err := ParseDNSResponse(b)
		if err == nil || got != nil {
			t.Fatalf("bad counts accepted: %v %v", got, err)
		}
	}
	for _, pointer := range []uint16{0xc00c, 0xffff} {
		b := make([]byte, 28)
		b[2] = 0x80
		b[7] = 1
		binary.BigEndian.PutUint16(b[12:14], pointer)
		b[15] = 1
		b[17] = 1
		b[23] = 4
		copy(b[24:], []byte{192, 0, 2, 1})
		a, err := ParseDNSResponse(b)
		if err != nil || len(a) != 1 {
			t.Fatalf("pointer semantics changed: %v %v", a, err)
		}
		t.Logf("security: pointer %#x treated as opaque, no dereference", pointer)
		b[7] = 2
		a, err = ParseDNSResponse(b)
		if err == nil || a != nil {
			t.Fatalf("partial result escaped malformed second answer: %v %v", a, err)
		}
	}
}

func TestSecurityGzipMemberBudget(t *testing.T) {
	var b bytes.Buffer
	for i := 0; i < 2; i++ {
		g := gzip.NewWriter(&b)
		_, err := io.WriteString(g, strings.Repeat("a.example\n", 20))
		if err != nil {
			t.Fatal(err)
		}
		if err = g.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	_, err := NormalizeList(context.Background(), ListInput{Reader: bytes.NewReader(b.Bytes())}, &out, nil, ListNormalizeOptions{Kind: ListKindDomain, MaxDecompressedBytes: 256})
	if err == nil || !strings.Contains(err.Error(), "decompressed size limit") || out.Len() != 0 {
		t.Fatalf("multimember budget failed: %v out=%d", err, out.Len())
	}
}

// Small deterministic inputs, not a load test: 128 or 256 entries on each side.
// This verifies real disjoint-list behavior. A separate isolated instrumentation
// control counts comparisons and the placement of context checks, not time.
func TestSecurityIPExclusionDisjointControl(t *testing.T) {
	for _, n := range []int{128, 256} {
		var in, exclude strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&in, "192.0.2.%d\n", i)
			fmt.Fprintf(&exclude, "198.51.100.%d\n", i)
		}
		var out bytes.Buffer
		manifest, err := NormalizeList(context.Background(), ListInput{Reader: strings.NewReader(in.String())}, &out, []ListInput{{Reader: strings.NewReader(exclude.String())}}, ListNormalizeOptions{Kind: ListKindIP})
		if err != nil || manifest.Output.Entries != n {
			t.Fatalf("bad disjoint result: %v entries=%d", err, manifest.Output.Entries)
		}
		t.Logf("security: disjoint IP input=%d excluded=%d retained=%d", n, n, manifest.Output.Entries)
	}
}
