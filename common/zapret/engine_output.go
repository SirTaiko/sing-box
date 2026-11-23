package zapret

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

const (
	outputTailLines = 24
	maxEngineLine   = 8192
)

func withEngineDebug(arguments []string) []string {
	if os.Getenv("MVPN_ZAPRET_DEBUG") == "1" {
		return append([]string{"--debug=1"}, arguments...)
	}
	return arguments
}

type engineTail struct {
	lines       [outputTailLines]string
	next, count int
}

func (t *engineTail) add(line string) {
	t.lines[t.next] = line
	t.next = (t.next + 1) % len(t.lines)
	if t.count < len(t.lines) {
		t.count++
	}
}

func (t *engineTail) String() string {
	if t.count == 0 {
		return "<no output>"
	}
	var out strings.Builder
	oldest := (t.next - t.count + len(t.lines)) % len(t.lines)
	for i := 0; i < t.count; i++ {
		if i != 0 {
			out.WriteString(" | ")
		}
		out.WriteString(t.lines[(oldest+i)%len(t.lines)])
	}
	return out.String()
}

// os/exec has one writer per pipe. Wait drains both before flushing the final
// partial lines. Only split or oversized lines need a scratch buffer.
type engineLineWriter struct {
	pending   []byte
	truncated bool
	line      func(string)
}

func (w *engineLineWriter) keep(p []byte) {
	n := min(len(p), maxEngineLine-len(w.pending))
	w.pending = append(w.pending, p[:n]...)
	if n < len(p) {
		w.truncated = true
	}
}

func (w *engineLineWriter) emit(p []byte) {
	if len(w.pending) == 0 && !w.truncated && len(p) <= maxEngineLine {
		w.line(string(p))
		return
	}
	w.keep(p)
	line := string(w.pending)
	if w.truncated {
		line += " [truncated]"
	}
	w.line(line)
	w.pending = w.pending[:0]
	w.truncated = false
}

func (w *engineLineWriter) Write(p []byte) (int, error) {
	size := len(p)
	for len(p) > 0 {
		next := bytes.IndexByte(p, '\n')
		if next < 0 {
			w.keep(p)
			break
		}
		w.emit(p[:next])
		p = p[next+1:]
	}
	return size, nil
}

func (w *engineLineWriter) flush() {
	if len(w.pending) > 0 || w.truncated {
		w.emit(nil)
	}
}

func attachEngineOutput(cmd *exec.Cmd, options platformOptions, record func(string)) func() {
	writer := func(logLine func(...any)) *engineLineWriter {
		return &engineLineWriter{line: func(line string) {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				record(trimmed)
				logLine("zapret[", options.tag, "]: ", trimmed)
			}
		}}
	}
	stdout, stderr := writer(options.logger.Debug), writer(options.logger.Error)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return func() { stdout.flush(); stderr.flush() }
}
