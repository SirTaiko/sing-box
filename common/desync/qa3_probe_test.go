package desync

// QA v3 independent probe (tester-max-2, task t_50f4d699).
//
// Reads the same fixture manifest as qa3/oracle.c, resolves every marker and
// offset through the shipped production entry points (ParsePosition ->
// streamBlockFacts -> resolveStreamPosition) and prints the identical line
// format, so the two outputs can be compared with `diff`. Nothing in this file
// invents expectations: the expectations come from the pinned C build.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

var qa3Offsets = []int{-3, -2, -1, 0, 1, 2, 3}
var qa3Markers = []string{"abs", "host", "endhost", "sld", "midsld", "endsld", "sniext", "method"}

func TestQA3Probe(t *testing.T) {
	manifestPath := os.Getenv("QA3_MANIFEST")
	outPath := os.Getenv("QA3_OUT")
	if manifestPath == "" || outPath == "" {
		t.Skip("QA3_MANIFEST/QA3_OUT not set")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("bad manifest line %q", line)
		}
		name, proto, path := fields[0], fields[1], fields[2]
		block, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		protocol := ProtocolTLS
		if proto == "http" {
			protocol = ProtocolHTTP
		}
		set := streamBlockFacts(protocol, block)
		for _, marker := range qa3Markers {
			for _, offset := range qa3Offsets {
				value := 0
				if marker == "abs" && offset == 0 {
					value = 0 // upstream: CheckPos(sz, 0) on a non-empty block
				} else {
					spelling := marker
					if marker == "abs" {
						spelling = strconv.Itoa(offset)
					} else if offset > 0 {
						spelling = marker + "+" + strconv.Itoa(offset)
					} else if offset < 0 {
						spelling = marker + strconv.Itoa(offset)
					}
					position, err := ParsePosition(spelling)
					if err != nil {
						t.Fatalf("%s: ParsePosition(%q): %v", name, spelling, err)
					}
					value = resolveStreamPosition(position, set, protocol)
				}
				fmt.Fprintf(out, "%s\t%s\t%s\t%d\t%d\n", name, proto, marker, offset, value)
			}
		}
	}
}
