package zapret

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestEngineOutputSplitsAndBoundsLines(t *testing.T) {
	var lines []string
	w := engineLineWriter{line: func(s string) { lines = append(lines, s) }}
	for _, p := range []string{"ab", "c\r\nx\n", strings.Repeat("s", maxEngineLine+100), "\ny\n", strings.Repeat("x", 4*maxEngineLine) + "\nlast"} {
		if n, err := w.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatal(n, err)
		}
	}
	w.flush()
	w.flush()
	want := []string{"abc\r", "x", strings.Repeat("s", maxEngineLine) + " [truncated]", "y", strings.Repeat("x", maxEngineLine) + " [truncated]", "last"}
	if !slices.Equal(lines, want) {
		t.Fatal("split, truncated or final line mismatch")
	}
}

type outputLogger struct{ debug, failures []string }

func (l *outputLogger) Info(...any)       {}
func (l *outputLogger) Debug(args ...any) { l.debug = append(l.debug, fmt.Sprint(args...)) }
func (l *outputLogger) Error(args ...any) { l.failures = append(l.failures, fmt.Sprint(args...)) }

func TestEngineOutputKeepsTheLatestDiagnostics(t *testing.T) {
	cmd := new(exec.Cmd)
	logger := new(outputLogger)
	var tail engineTail
	if tail.String() != "<no output>" {
		t.Fatal("nonempty initial tail")
	}
	flush := attachEngineOutput(cmd, platformOptions{tag: "unit", logger: logger}, tail.add)
	for i := 0; i < 30; i++ {
		fmt.Fprintf(cmd.Stdout, "entry-%d\r\n", i)
	}
	fmt.Fprint(cmd.Stderr, "  engine error  ")
	flush()
	if len(logger.debug) != 30 || !slices.Equal(logger.failures, []string{"zapret[unit]: engine error"}) {
		t.Fatal("stdout/stderr severity lost")
	}
	lines := strings.Split(tail.String(), " | ")
	if len(lines) != outputTailLines || lines[0] != "entry-7" || lines[len(lines)-1] != "engine error" {
		t.Fatal(lines)
	}
}

func TestEnginePacketDebugIsExplicit(t *testing.T) {
	base := []string{"--intercept=1"}
	for _, value := range []string{"", "0", "1"} {
		t.Setenv("MVPN_ZAPRET_DEBUG", value)
		args := withEngineDebug(base)
		if slices.Contains(args, "--debug=1") != (value == "1") || args[len(args)-1] != "--intercept=1" {
			t.Fatalf("unexpected arguments for %q", value)
		}
	}
}
