//go:build linux

package zapret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// nftCommandTimeout bounds every nftables invocation. The binaries are
	// short-lived and only speak netlink; a hung nft must not hang shutdown.
	nftCommandTimeout = 15 * time.Second
	// maxNftOutput bounds retained command output so a huge ruleset cannot
	// grow the log or the error message without limit.
	maxNftOutput = 8 << 20
	// maxNftErrorOutput is the part of an nft failure included in errors.
	maxNftErrorOutput = 2048
)

// nftState is the subset of `nft -j list ruleset` this slice needs: table
// names and rule expressions. Everything else is ignored.
type nftState struct {
	tables []nftTable
	rules  []nftRule
}

type nftTable struct {
	family string
	name   string
}

type nftRule struct {
	family string
	table  string
	chain  string
	expr   []map[string]json.RawMessage
}

// readNftState loads and parses the complete ruleset of the current network
// namespace. It is read-only: the ownership table is never modified here.
func (e *linuxEngine) readNftState(ctx context.Context) (*nftState, error) {
	output, err := runNftCommand(ctx, e.nftPath, "", "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("zapret: outbound %q: list the existing nftables ruleset: %w; nft output: %s (CAP_NET_ADMIN and the nftables user space tools are required)", e.options.tag, err, output.describe())
	}
	state, err := parseNftState(output.stdout)
	if err != nil {
		return nil, fmt.Errorf("zapret: outbound %q: parse the existing nftables ruleset: %w", e.options.tag, err)
	}
	return state, nil
}

func parseNftState(content []byte) (*nftState, error) {
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	err := json.Unmarshal(content, &document)
	if err != nil {
		return nil, err
	}
	state := &nftState{}
	for _, rawEntry := range document.Nftables {
		var entry struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
			Rule *struct {
				Family string                       `json:"family"`
				Table  string                       `json:"table"`
				Chain  string                       `json:"chain"`
				Expr   []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		}
		err = json.Unmarshal(rawEntry, &entry)
		if err != nil {
			return nil, err
		}
		if entry.Table != nil {
			state.tables = append(state.tables, nftTable{family: entry.Table.Family, name: entry.Table.Name})
		}
		if entry.Rule != nil {
			state.rules = append(state.rules, nftRule{
				family: entry.Rule.Family,
				table:  entry.Rule.Table,
				chain:  entry.Rule.Chain,
				expr:   entry.Rule.Expr,
			})
		}
	}
	return state, nil
}

func (s *nftState) tableExists(family string, name string) bool {
	for _, table := range s.tables {
		if table.family == family && table.name == name {
			return true
		}
	}
	return false
}

// nftQueueRange is the closed interval of queue numbers one queue statement
// can deliver packets to. nftables serializes `queue num N` as the plain
// number N and `queue num A-B` as {"range":[A,B]}; `num` itself is an
// EXPRESSION, so every other form is unresolved instead of unused.
type nftQueueRange struct {
	lower uint32
	upper uint32
}

func parseNftQueueRange(rawNum json.RawMessage) (nftQueueRange, error) {
	var single uint32
	if err := json.Unmarshal(rawNum, &single); err == nil {
		return nftQueueRange{lower: single, upper: single}, nil
	}
	var expression struct {
		Range []json.RawMessage `json:"range"`
	}
	if err := json.Unmarshal(rawNum, &expression); err == nil && expression.Range != nil {
		if len(expression.Range) != 2 {
			return nftQueueRange{}, fmt.Errorf("queue num range has %d bounds instead of 2", len(expression.Range))
		}
		var lower, upper uint32
		if err := json.Unmarshal(expression.Range[0], &lower); err != nil {
			return nftQueueRange{}, fmt.Errorf("queue num range lower bound is not a queue number: %w", err)
		}
		if err := json.Unmarshal(expression.Range[1], &upper); err != nil {
			return nftQueueRange{}, fmt.Errorf("queue num range upper bound is not a queue number: %w", err)
		}
		if lower > upper {
			return nftQueueRange{}, fmt.Errorf("queue num range %d-%d has a lower bound above its upper bound", lower, upper)
		}
		return nftQueueRange{lower: lower, upper: upper}, nil
	}
	return nftQueueRange{}, fmt.Errorf("unsupported queue num expression %s", describeNftOutput(rawNum))
}

// queueUsed reports whether any existing rule can deliver packets to the queue.
// A queue rule of another program must never receive this outbound's packets,
// so queue statements are resolved to their actual number expression: a
// scalar, a range covering the candidate, or an explicit error when the
// expression cannot be resolved. A decode failure is never treated as unused.
func (s *nftState) queueUsed(queue int) (bool, error) {
	for _, rule := range s.rules {
		for _, expression := range rule.expr {
			rawQueue, loaded := expression["queue"]
			if !loaded {
				continue
			}
			var statement struct {
				// `queue num` is an nftables expression, not a fixed integer:
				// a plain number, a range, or an unresolved variable/set form.
				Num json.RawMessage `json:"num"`
			}
			err := json.Unmarshal(rawQueue, &statement)
			if err != nil {
				return false, fmt.Errorf("rule in %s table %q chain %q: decode the queue statement: %w", rule.family, rule.table, rule.chain, err)
			}
			if statement.Num == nil {
				return false, fmt.Errorf("rule in %s table %q chain %q: the queue statement has no num expression, so its queue cannot be resolved; remove it or make the queue number explicit before starting a zapret outbound", rule.family, rule.table, rule.chain)
			}
			interval, err := parseNftQueueRange(statement.Num)
			if err != nil {
				return false, fmt.Errorf("rule in %s table %q chain %q: %w; refusing to allocate a queue that an unresolved queue expression could also select", rule.family, rule.table, rule.chain, err)
			}
			if uint32(queue) >= interval.lower && uint32(queue) <= interval.upper {
				return true, nil
			}
		}
	}
	return false, nil
}

// markUsed reports whether any existing rule positively selects the exact
// mark. Meta and socket mark selectors are both ownership-relevant: a foreign
// meta mark rule could route or queue this outbound's packets, and a foreign
// socket mark rule could steal its replies. Negative selectors ("mark != X")
// are not treated as a conflict because they do not claim the mark.
func (s *nftState) markUsed(mark uint32) bool {
	for _, rule := range s.rules {
		for _, expression := range rule.expr {
			rawMatch, loaded := expression["match"]
			if !loaded {
				continue
			}
			if nftMatchSelectsMark(rawMatch, mark) {
				return true
			}
		}
	}
	return false
}

func nftMatchSelectsMark(rawMatch json.RawMessage, mark uint32) bool {
	var match struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	err := json.Unmarshal(rawMatch, &match)
	if err != nil {
		return false
	}
	mask, isMark := nftMarkMask(match.Left)
	if !isMark {
		return false
	}
	value := mark & mask
	return nftRightMatchesValue(match.Right, match.Op, value)
}

// nftMarkMask returns the value mask applied to a mark expression. A plain
// `meta mark` or `socket mark` has a full mask; `meta mark & 0xff` is the
// binary-and form nftables serializes as {"&": [<mark>, <mask>]}.
func nftMarkMask(rawExpression json.RawMessage) (uint32, bool) {
	var expression struct {
		Meta *struct {
			Key string `json:"key"`
		} `json:"meta"`
		Socket *struct {
			Key string `json:"key"`
		} `json:"socket"`
		And []json.RawMessage `json:"&"`
	}
	err := json.Unmarshal(rawExpression, &expression)
	if err != nil {
		return 0, false
	}
	if expression.Meta != nil && expression.Meta.Key == "mark" {
		return 0xFFFFFFFF, true
	}
	if expression.Socket != nil && expression.Socket.Key == "mark" {
		return 0xFFFFFFFF, true
	}
	if len(expression.And) == 2 {
		innerMask, isMark := nftMarkMask(expression.And[0])
		if !isMark {
			return 0, false
		}
		var mask uint32
		if json.Unmarshal(expression.And[1], &mask) != nil {
			return 0, false
		}
		return innerMask & mask, true
	}
	return 0, false
}

func nftRightMatchesValue(rawRight json.RawMessage, op string, value uint32) bool {
	var scalar uint32
	if json.Unmarshal(rawRight, &scalar) == nil {
		switch op {
		case "==":
			return value == scalar
		case "<":
			return value < scalar
		case ">":
			return value > scalar
		case "<=":
			return value <= scalar
		case ">=":
			return value >= scalar
		default:
			return false
		}
	}
	var collection struct {
		Range []uint32 `json:"range"`
		Set   []uint32 `json:"set"`
	}
	if json.Unmarshal(rawRight, &collection) == nil {
		if op != "==" {
			return false
		}
		if len(collection.Range) == 2 && value >= collection.Range[0] && value <= collection.Range[1] {
			return true
		}
		for _, candidate := range collection.Set {
			if candidate == value {
				return true
			}
		}
	}
	return false
}

// rulesetScript builds the single nftables transaction that owns this
// outbound. The table is created and populated in one `nft -f` batch, so a
// partially installed ownership table cannot be observed:
//
//   - output priority -401 keeps packets generated by the original engine
//     untracked, so NAT cannot reject its raw packets;
//   - postrouting after SNAT queues the outbound's own TCP/UDP packets by
//     their exact socket mark;
//   - input queues replies by the live socket mark lookup, which is what makes
//     unconnected (wildcard bound) UDP sockets work without transparent or
//     wildcard socket options;
//   - no queue has the bypass flag: if the engine is gone, owned packets are
//     dropped instead of silently continuing without processing.
func (e *linuxEngine) rulesetScript() string {
	var builder strings.Builder
	write := func(format string, arguments ...any) {
		fmt.Fprintf(&builder, format, arguments...)
	}
	write("add table inet %s\n", e.table)
	write("add chain inet %s predefrag { type filter hook output priority -401; policy accept; }\n", e.table)
	write("add rule inet %s predefrag meta mark & 0x%08x != 0 notrack comment \"zapret generated packets\"\n", e.table, generatedMark)
	write("add chain inet %s postrouting { type filter hook postrouting priority srcnat + 1; policy accept; }\n", e.table)
	for _, protocol := range []string{"tcp", "udp"} {
		write("add rule inet %s postrouting oifname \"%s\" meta mark == 0x%08x meta l4proto %s counter queue num %d comment \"owned %s egress\"\n", e.table, e.options.bindInterface, e.mark, protocol, e.queue, protocol)
	}
	write("add chain inet %s input { type filter hook input priority filter; policy accept; }\n", e.table)
	for _, protocol := range []string{"tcp", "udp"} {
		write("add rule inet %s input iifname \"%s\" socket mark == 0x%08x meta l4proto %s counter queue num %d comment \"owned %s ingress\"\n", e.table, e.options.bindInterface, e.mark, protocol, e.queue, protocol)
	}
	return builder.String()
}

// installTable applies the ownership table in one atomic transaction.
func (e *linuxEngine) installTable(ctx context.Context) error {
	output, err := runNftCommand(ctx, e.nftPath, e.rulesetScript(), "-f", "-")
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: install the ownership nft table %q: %w; nft output: %s (nftables >= 1.0.1 and the nf_socket kernel module are required)", e.options.tag, e.table, err, output.describe())
	}
	return nil
}

// verifyTable confirms that the transaction installed exactly the four queue
// rules of this outbound. Anything else is a hard startup error, not READY.
func (e *linuxEngine) verifyTable(ctx context.Context) error {
	output, err := runNftCommand(ctx, e.nftPath, "", "-j", "list", "table", "inet", e.table)
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: read back the ownership nft table %q: %w; nft output: %s", e.options.tag, e.table, err, output.describe())
	}
	state, err := parseNftState(output.stdout)
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: parse the ownership nft table %q: %w", e.options.tag, e.table, err)
	}
	if !state.tableExists("inet", e.table) {
		return fmt.Errorf("zapret: outbound %q: ownership nft table %q is missing after install", e.options.tag, e.table)
	}
	queueRules := 0
	for _, rule := range state.rules {
		for _, expression := range rule.expr {
			rawQueue, loaded := expression["queue"]
			if !loaded {
				continue
			}
			var statement struct {
				Num *int `json:"num"`
			}
			if json.Unmarshal(rawQueue, &statement) == nil && statement.Num != nil && *statement.Num == e.queue {
				queueRules++
			}
		}
	}
	if queueRules != 4 {
		return fmt.Errorf("zapret: outbound %q: ownership nft table %q contains %d queue %d rules, expected 4", e.options.tag, e.table, queueRules, e.queue)
	}
	return nil
}

// tableExists reports whether the managed table already exists in the inet
// family. A stale table from an earlier unclean stop is an explicit error: it
// is never overwritten, reflushed or silently replaced by a different queue.
func (e *linuxEngine) tableExists(ctx context.Context) (bool, error) {
	output, err := runNftCommand(ctx, e.nftPath, "", "-j", "list", "tables")
	if err != nil {
		return false, fmt.Errorf("zapret: outbound %q: list nftables tables: %w; nft output: %s", e.options.tag, err, output.describe())
	}
	state, err := parseNftState(output.stdout)
	if err != nil {
		return false, fmt.Errorf("zapret: outbound %q: parse nftables tables: %w", e.options.tag, err)
	}
	return state.tableExists("inet", e.table), nil
}

// removeTable deletes only the managed inet table. The whole rule set is never
// flushed and foreign tables are never touched.
func (e *linuxEngine) removeTable(ctx context.Context) error {
	if e.nftPath == "" || e.table == "" {
		return nil
	}
	output, err := runNftCommand(ctx, e.nftPath, "", "delete", "table", "inet", e.table)
	if err == nil {
		return nil
	}
	exists, existsErr := e.tableExists(ctx)
	if existsErr != nil {
		return fmt.Errorf("zapret: outbound %q: delete the ownership nft table %q: %w; presence check: %v; nft output: %s", e.options.tag, e.table, err, existsErr, output.describe())
	}
	if exists {
		return fmt.Errorf("zapret: outbound %q: ownership nft table %q remains after delete: %w; nft output: %s", e.options.tag, e.table, err, output.describe())
	}
	// The table is already absent: nothing of this outbound is left behind.
	return nil
}

// nftOutput is the result of one nft invocation with the two streams kept
// apart. nft reports nonfatal warnings about pre-existing foreign rules on
// standard error even when the command succeeds, so structured (-j) output may
// only ever be decoded from standard output.
type nftOutput struct {
	stdout []byte
	stderr []byte
}

// describe renders a failed invocation for an error message. Both streams are
// bounded and labelled: standard error carries nft's own diagnostics, while a
// non-empty standard output is still shown so partial data is not lost.
func (o nftOutput) describe() string {
	parts := make([]string, 0, 2)
	if stderr := strings.TrimSpace(string(o.stderr)); stderr != "" {
		parts = append(parts, "stderr: "+stderr)
	}
	if stdout := strings.TrimSpace(string(o.stdout)); stdout != "" {
		parts = append(parts, "stdout: "+stdout)
	}
	return describeNftOutput([]byte(strings.Join(parts, " | ")))
}

// runNftCommand runs the ready user space nft binary without a shell. The
// script is passed on standard input as one batch, so it is applied atomically.
// Standard output and standard error are captured separately: nonfatal warnings
// must never be merged into a structured response.
func runNftCommand(ctx context.Context, nftPath string, stdin string, arguments ...string) (nftOutput, error) {
	commandContext, cancel := context.WithTimeout(ctx, nftCommandTimeout)
	defer cancel()
	command := exec.CommandContext(commandContext, nftPath, arguments...)
	if stdin != "" {
		command.Stdin = bytes.NewBufferString(stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	output := nftOutput{
		stdout: boundedNftOutput(stdout.Bytes()),
		stderr: boundedNftOutput(stderr.Bytes()),
	}
	if err != nil {
		// exec reports a killed child as "signal: killed"; name the cause so
		// a timeout or cancellation stays distinguishable from an nft failure.
		if contextErr := commandContext.Err(); contextErr != nil {
			return output, fmt.Errorf("nft command aborted: %w", contextErr)
		}
	}
	return output, err
}

func boundedNftOutput(content []byte) []byte {
	if len(content) > maxNftOutput {
		return content[:maxNftOutput]
	}
	return content
}

func describeNftOutput(output []byte) string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return "<no output>"
	}
	text = strings.ReplaceAll(text, "\n", " | ")
	if len(text) > maxNftErrorOutput {
		text = text[:maxNftErrorOutput] + "..."
	}
	return text
}
