package windivert

// WinDivert filter language compiler.
//
// The driver installs a filter as a 256-entry decision tree of 24-byte
// instructions (see filter.go). The constructors in filter.go build the owned
// capture envelope directly; this file adds the two things an owned envelope
// needs before a user expression can be trusted:
//
//  1. a validated parser/compiler for the driver's filter language, so a raw
//     user expression becomes instructions instead of being forwarded as an
//     opaque blob, and
//  2. logical composition (And/Or/Not), so an envelope can be AND-ed with a
//     fully parenthesized user expression. Composition NEVER widens ownership:
//     the resulting filter matches a packet only when both operands match.
//
// Only the documented WINDIVERT_FILTER fields/operators listed in
// filterFieldNames are accepted. Anything else (unknown field, unknown
// operator, malformed number, unbalanced parenthesis, over-long expression)
// is an explicit error. Silent acceptance of an unparsed expression would
// turn a mistyped filter into an ownership bypass, so it is not an option.
//
// The compiler is pure Go and platform independent: the same instructions are
// produced on every OS and are exercised by the hermetic VM tests. Only the
// driver itself (windivert.Open) is Windows-specific.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Extra WINDIVERT_FILTER_FIELD_* values used by the filter language but not by
// the owned envelope constructors. They complete the contiguous field table
// from windivert.h (the already pinned values 38/39/53/54 fix the ordering).
const (
	fieldIfIdx               = 3
	fieldSubIfIdx            = 4
	fieldTCPUrg              = 43
	fieldTCPAck              = 44
	fieldTCPPsh              = 45
	fieldTCPRst              = 46
	fieldTCPSyn              = 47
	fieldTCPFin              = 48
	fieldTCPPayloadLen       = 52
	fieldUDPPayloadLen       = 57
	fieldLoopback            = 64
	fieldImpostor            = 65
	testNEQ            uint8 = 1
	testLT             uint8 = 2
	testGT             uint8 = 4
)

// Filter expression bounds. The driver's own limit is 256 instructions; the
// textual bound keeps a hostile or accidentally huge expression from consuming
// unbounded memory before that limit is reached.
const (
	filterMaxExpressionBytes = 16 * 1024
	filterMaxTokens          = 4096
	filterMaxDepth           = 64
)

type filterNodeKind uint8

const (
	nodeConst filterNodeKind = iota
	nodeTest
	nodeAnd
	nodeOr
	nodeNot
)

type filterNode struct {
	kind  filterNodeKind
	value bool // nodeConst
	field uint16
	test  uint8
	arg   [4]uint32
	left  *filterNode
	right *filterNode
}

func constNode(value bool) *filterNode { return &filterNode{kind: nodeConst, value: value} }

func testNode(field uint16, test uint8, arg [4]uint32) *filterNode {
	return &filterNode{kind: nodeTest, field: field, test: test, arg: arg}
}

func booleanNode(field uint16) *filterNode {
	// `tcp.Syn` used without a comparison is `tcp.Syn != 0`.
	return testNode(field, testNEQ, argUint32(0))
}

func andNode(left, right *filterNode) *filterNode {
	return foldBinary(nodeAnd, left, right)
}

func orNode(left, right *filterNode) *filterNode {
	return foldBinary(nodeOr, left, right)
}

func notNode(node *filterNode) *filterNode {
	switch node.kind {
	case nodeConst:
		return constNode(!node.value)
	case nodeNot:
		return node.left
	}
	return &filterNode{kind: nodeNot, left: node}
}

// foldBinary applies the boolean identities that keep the emitted instruction
// count proportional to the written expression. Constants never reach the
// emitter.
func foldBinary(kind filterNodeKind, left, right *filterNode) *filterNode {
	kindName := kind == nodeAnd
	if left.kind == nodeConst {
		if left.value == kindName {
			return right
		}
		return constNode(!kindName)
	}
	if right.kind == nodeConst {
		if right.value == kindName {
			return left
		}
		return constNode(!kindName)
	}
	return &filterNode{kind: kind, left: left, right: right}
}

// Filter is a compiled WinDivert filter: a boolean expression plus the
// direction/family callout flags the driver needs to see the packets the
// expression names. anyNodes holds the constructors' "one of" tail: the
// filter matches when root matches AND at least one any-node matches, which is
// exactly the historical insts/anyInsts encoding.
type Filter struct {
	root     *filterNode
	anyNodes []*filterNode
	flags    uint64
}

func newFilterNode(flags uint64) *Filter {
	return &Filter{root: constNode(true), flags: flags}
}

// tree combines the AND chain with the "any of" tail, if present.
func (f *Filter) tree() (*filterNode, error) {
	if f == nil || f.root == nil {
		return nil, E.New("windivert: filter: uninitialized filter")
	}
	root := f.root
	if len(f.anyNodes) > 0 {
		any := f.anyNodes[0]
		for _, node := range f.anyNodes[1:] {
			if node == nil {
				return nil, E.New("windivert: filter: uninitialized alternative")
			}
			any = orNode(any, node)
		}
		if any == nil {
			return nil, E.New("windivert: filter: uninitialized alternative")
		}
		root = andNode(root, any)
	}
	return root, nil
}

func reject() *Filter {
	return &Filter{root: constNode(false)}
}

// Expression renders the filter as a canonical, fully parenthesized filter
// string. Parsing the rendering again yields the same filter; the captured
// envelope and any user expression therefore have one inspectable form.
func (f *Filter) Expression() string {
	if f == nil {
		return "false"
	}
	root, err := f.tree()
	if err != nil {
		return "false"
	}
	return root.render()
}

func (n *filterNode) render() string {
	switch n.kind {
	case nodeConst:
		if n.value {
			return "true"
		}
		return "false"
	case nodeNot:
		return "(not " + n.left.render() + ")"
	case nodeAnd:
		return "(" + n.left.render() + " and " + n.right.render() + ")"
	case nodeOr:
		return "(" + n.left.render() + " or " + n.right.render() + ")"
	case nodeTest:
		field, ok := filterFieldName(n.field)
		if !ok {
			field = fmt.Sprintf("<field %d>", n.field)
		}
		if n.field == fieldInbound || n.field == fieldOutbound || n.field == fieldIP ||
			n.field == fieldIPv6 || n.field == fieldTCP || n.field == fieldUDP {
			// Boolean protocol/direction fields render as their language form.
			if n.test == testNEQ && n.arg[0] == 0 {
				return field
			}
			if n.test == testEQ && n.arg[0] == 0 {
				return "!" + field
			}
		}
		operator, ok := filterTestOperator(n.test)
		if !ok {
			operator = fmt.Sprintf("<test %d>", n.test)
		}
		return fmt.Sprintf("%s %s %s", field, operator, renderValue(n.field, n.arg))
	default:
		return "false"
	}
}

func renderValue(field uint16, arg [4]uint32) string {
	switch field {
	case fieldIPSrcAddr, fieldIPDstAddr:
		var raw [4]byte
		value := arg[0]
		raw[0] = byte(value >> 24)
		raw[1] = byte(value >> 16)
		raw[2] = byte(value >> 8)
		raw[3] = byte(value)
		return netip.AddrFrom4(raw).String()
	case fieldIPv6SrcAddr, fieldIPv6DstAddr:
		var raw [16]byte
		words := [4]uint32{arg[3], arg[2], arg[1], arg[0]}
		for index, word := range words {
			raw[index*4+0] = byte(word >> 24)
			raw[index*4+1] = byte(word >> 16)
			raw[index*4+2] = byte(word >> 8)
			raw[index*4+3] = byte(word)
		}
		return netip.AddrFrom16(raw).String()
	}
	if arg[1] == 0 && arg[2] == 0 && arg[3] == 0 {
		return strconv.FormatUint(uint64(arg[0]), 10)
	}
	return fmt.Sprintf("0x%08x%08x%08x%08x", arg[3], arg[2], arg[1], arg[0])
}

// And returns the filter that matches a packet only when both operands match.
// This is the composition that keeps a user expression inside the owned
// envelope: there is no way for an `or` or a negation inside right to satisfy
// left.
func And(left, right *Filter) (*Filter, error) {
	if left == nil || right == nil {
		return nil, E.New("windivert: filter composition: nil operand")
	}
	leftRoot, err := left.tree()
	if err != nil {
		return nil, err
	}
	rightRoot, err := right.tree()
	if err != nil {
		return nil, err
	}
	return &Filter{root: andNode(leftRoot, rightRoot), flags: left.flags | right.flags}, nil
}

// Or returns the filter that matches when either operand matches.
func Or(left, right *Filter) (*Filter, error) {
	if left == nil || right == nil {
		return nil, E.New("windivert: filter composition: nil operand")
	}
	leftRoot, err := left.tree()
	if err != nil {
		return nil, err
	}
	rightRoot, err := right.tree()
	if err != nil {
		return nil, err
	}
	return &Filter{root: orNode(leftRoot, rightRoot), flags: left.flags | right.flags}, nil
}

// Not returns the complement of filter.
func Not(filter *Filter) (*Filter, error) {
	if filter == nil {
		return nil, E.New("windivert: filter composition: uninitialized operand")
	}
	root, err := filter.tree()
	if err != nil {
		return nil, err
	}
	return &Filter{root: notNode(root), flags: filter.flags}, nil
}

// InstructionCount reports how many VM instructions the filter compiles to.
// The caller can use it to reject an expression that is legal but too large to
// be practical before any native resource is opened.
func (f *Filter) InstructionCount() int {
	if f == nil {
		return 0
	}
	root, err := f.tree()
	if err != nil {
		return -1
	}
	emitted, err := compileTree(root)
	if err != nil {
		return -1
	}
	return len(emitted)
}

// encode compiles the filter tree to the driver's instruction array.
func (f *Filter) encode() ([]byte, uint64, error) {
	if f == nil {
		return nil, 0, E.New("windivert: filter: uninitialized filter")
	}
	root, err := f.tree()
	if err != nil {
		return nil, 0, err
	}
	return compileAndEncode(root, f.flags)
}

func compileAndEncode(root *filterNode, flags uint64) ([]byte, uint64, error) {
	insts, err := compileTree(root)
	if err != nil {
		return nil, 0, err
	}
	if len(insts) == 0 {
		// A filter that matches everything is the always-true ZERO test.
		insts = []filterInst{{field: fieldZero, test: testEQ, success: resultAccept, failure: resultReject}}
	}
	out := make([]byte, 0, filterInstBytes*len(insts))
	for _, inst := range insts {
		out = append(out, encodeInst(inst)...)
	}
	return out, flags, nil
}

type filterLabel int

const noLabel filterLabel = -1

type filterContinuation struct {
	terminal uint16
	label    filterLabel
}

func acceptContinuation() filterContinuation {
	return filterContinuation{terminal: resultAccept, label: noLabel}
}

func rejectContinuation() filterContinuation {
	return filterContinuation{terminal: resultReject, label: noLabel}
}

func labelContinuation(label filterLabel) filterContinuation {
	return filterContinuation{label: label}
}

type filterPatch struct {
	instruction int
	success     bool
	label       filterLabel
}

type filterEmitter struct {
	insts   []filterInst
	labels  map[filterLabel]int
	patches []filterPatch
}

func (e *filterEmitter) newLabel() filterLabel {
	label := filterLabel(len(e.labels) + 1)
	e.labels[label] = -1
	return label
}

func (e *filterEmitter) place(label filterLabel) {
	e.labels[label] = len(e.insts)
}

func (e *filterEmitter) apply(instruction int, success bool, continuation filterContinuation) {
	if continuation.label == noLabel {
		if success {
			e.insts[instruction].success = continuation.terminal
		} else {
			e.insts[instruction].failure = continuation.terminal
		}
		return
	}
	e.patches = append(e.patches, filterPatch{instruction: instruction, success: success, label: continuation.label})
}

func (e *filterEmitter) emit(node *filterNode, success, failure filterContinuation) error {
	switch node.kind {
	case nodeConst:
		// Constants are folded before emission; a bare constant is handled by
		// the caller. Reaching here means the tree was built without folding.
		return E.New("windivert: filter compiler: unfolded constant")
	case nodeTest:
		if len(e.insts) >= filterMaxInsts {
			return E.New("windivert: filter too long (more than ", filterMaxInsts, " instructions)")
		}
		index := len(e.insts)
		e.insts = append(e.insts, filterInst{field: node.field, test: node.test, arg: node.arg})
		e.apply(index, true, success)
		e.apply(index, false, failure)
		return nil
	case nodeNot:
		return e.emit(node.left, failure, success)
	case nodeAnd:
		next := e.newLabel()
		if err := e.emit(node.left, labelContinuation(next), failure); err != nil {
			return err
		}
		e.place(next)
		return e.emit(node.right, success, failure)
	case nodeOr:
		next := e.newLabel()
		if err := e.emit(node.left, success, labelContinuation(next)); err != nil {
			return err
		}
		e.place(next)
		return e.emit(node.right, success, failure)
	default:
		return E.New("windivert: filter compiler: unknown node")
	}
}

func compileTree(root *filterNode) ([]filterInst, error) {
	if root == nil {
		return nil, E.New("windivert: filter compiler: empty expression")
	}
	if root.kind == nodeConst {
		if root.value {
			return []filterInst{{field: fieldZero, test: testEQ, success: resultAccept, failure: resultReject}}, nil
		}
		return []filterInst{{field: fieldZero, test: testEQ, success: resultReject, failure: resultReject}}, nil
	}
	emitter := &filterEmitter{labels: make(map[filterLabel]int)}
	if err := emitter.emit(root, acceptContinuation(), rejectContinuation()); err != nil {
		return nil, err
	}
	for _, patch := range emitter.patches {
		target, ok := emitter.labels[patch.label]
		if !ok || target < 0 {
			return nil, E.New("windivert: filter compiler: unresolved continuation")
		}
		if target >= int(resultAccept) {
			return nil, E.New("windivert: filter compiler: continuation out of range")
		}
		if patch.success {
			emitter.insts[patch.instruction].success = uint16(target)
		} else {
			emitter.insts[patch.instruction].failure = uint16(target)
		}
	}
	if len(emitter.insts) > filterMaxInsts {
		return nil, E.New("windivert: filter too long (more than ", filterMaxInsts, " instructions)")
	}
	return emitter.insts, nil
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type filterTokenKind uint8

const (
	tokenEOF filterTokenKind = iota
	tokenIdentifier
	tokenNumber
	tokenAddress
	tokenOperator
	tokenLeftParen
	tokenRightParen
)

type filterToken struct {
	kind   filterTokenKind
	text   string
	number uint64
	addr   netip.Addr
	offset int
}

type filterLexer struct {
	input  string
	offset int
	tokens []filterToken
}

func lexFilter(input string) ([]filterToken, error) {
	if len(input) > filterMaxExpressionBytes {
		return nil, E.New("windivert: filter expression exceeds ", filterMaxExpressionBytes, " bytes")
	}
	lexer := &filterLexer{input: input}
	for {
		token, err := lexer.next()
		if err != nil {
			return nil, err
		}
		lexer.tokens = append(lexer.tokens, token)
		if len(lexer.tokens) > filterMaxTokens {
			return nil, E.New("windivert: filter expression has more than ", filterMaxTokens, " tokens")
		}
		if token.kind == tokenEOF {
			return lexer.tokens, nil
		}
	}
}

func (l *filterLexer) next() (filterToken, error) {
	for l.offset < len(l.input) {
		switch l.input[l.offset] {
		case ' ', '\t', '\r', '\n':
			l.offset++
			continue
		}
		break
	}
	if l.offset >= len(l.input) {
		return filterToken{kind: tokenEOF, offset: l.offset}, nil
	}
	start := l.offset
	character := l.input[l.offset]
	switch character {
	case '(':
		l.offset++
		return filterToken{kind: tokenLeftParen, text: "(", offset: start}, nil
	case ')':
		l.offset++
		return filterToken{kind: tokenRightParen, text: ")", offset: start}, nil
	}
	if character == '=' || character == '!' || character == '<' || character == '>' {
		return l.operator()
	}
	if isFilterDigit(character) || character == ':' || character == '[' || character == '-' || character == '.' {
		return l.value()
	}
	if isFilterIdentifierStart(character) {
		for l.offset < len(l.input) && isFilterIdentifierPart(l.input[l.offset]) {
			l.offset++
		}
		text := l.input[start:l.offset]
		switch text {
		case "and", "or", "not":
			return filterToken{kind: tokenIdentifier, text: text, offset: start}, nil
		}
		return filterToken{kind: tokenIdentifier, text: text, offset: start}, nil
	}
	return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": unexpected character ", strconv.QuoteRune(rune(character)))
}

func (l *filterLexer) operator() (filterToken, error) {
	start := l.offset
	for l.offset < len(l.input) {
		switch l.input[l.offset] {
		case '=', '!', '<', '>':
			l.offset++
			continue
		}
		break
	}
	text := l.input[start:l.offset]
	switch text {
	case "=", "==":
		text = "=="
	case "!", "!=", "<>":
		if text == "!" {
			// `!expr` is the language's short negation.
			return filterToken{kind: tokenOperator, text: "!", offset: start}, nil
		}
		text = "!="
	case "<", "<=", ">", ">=":
	default:
		return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": unknown operator ", strconv.Quote(text))
	}
	return filterToken{kind: tokenOperator, text: text, offset: start}, nil
}

// value lexes a numeric literal or an IP address. IPv6 literals contain ':' so
// the lexer must scan the whole address before deciding.
func (l *filterLexer) value() (filterToken, error) {
	start := l.offset
	for l.offset < len(l.input) {
		character := l.input[l.offset]
		if isFilterDigit(character) || isFilterHexLetter(character) ||
			character == '.' || character == ':' || character == '[' || character == ']' ||
			character == '/' || character == '%' || character == '-' {
			l.offset++
			continue
		}
		break
	}
	text := l.input[start:l.offset]
	if text == "" {
		return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": empty value")
	}
	if strings.Contains(text, ":") || strings.HasPrefix(text, "[") {
		trimmed := strings.TrimPrefix(strings.TrimSuffix(text, "]"), "[")
		address, err := netip.ParseAddr(trimmed)
		if err != nil {
			return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": invalid address ", strconv.Quote(text))
		}
		return filterToken{kind: tokenAddress, text: text, addr: address, offset: start}, nil
	}
	if strings.Count(text, ".") == 3 {
		address, err := netip.ParseAddr(text)
		if err != nil || !address.Is4() {
			return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": invalid IPv4 address ", strconv.Quote(text))
		}
		return filterToken{kind: tokenAddress, text: text, addr: address, offset: start}, nil
	}
	number, err := parseFilterNumber(text)
	if err != nil {
		return filterToken{}, E.New("windivert: filter parse error at offset ", start, ": ", err)
	}
	return filterToken{kind: tokenNumber, text: text, number: number, offset: start}, nil
}

func parseFilterNumber(text string) (uint64, error) {
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		value, err := strconv.ParseUint(text[2:], 16, 64)
		if err != nil {
			return 0, E.New("invalid hexadecimal number ", strconv.Quote(text))
		}
		return value, nil
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, E.New("invalid number ", strconv.Quote(text))
	}
	return value, nil
}

func isFilterDigit(character byte) bool { return character >= '0' && character <= '9' }

func isFilterHexLetter(character byte) bool {
	return (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')
}

func isFilterIdentifierStart(character byte) bool {
	return character == '_' || (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func isFilterIdentifierPart(character byte) bool {
	return isFilterIdentifierStart(character) || isFilterDigit(character) || character == '.'
}

type filterParser struct {
	tokens []filterToken
	index  int
	depth  int
}

// ParseFilter parses and compiles a WinDivert filter expression. The returned
// filter carries the direction/family callout flags implied by the fields it
// mentions, so composing it with an envelope keeps every flag either side
// needs.
func ParseFilter(expression string) (*Filter, error) {
	tokens, err := lexFilter(expression)
	if err != nil {
		return nil, err
	}
	parser := &filterParser{tokens: tokens}
	if parser.current().kind == tokenEOF {
		return nil, E.New("windivert: filter expression is empty")
	}
	root, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if token := parser.current(); token.kind != tokenEOF {
		return nil, E.New("windivert: filter parse error at offset ", token.offset, ": unexpected token ", strconv.Quote(token.text))
	}
	filter := &Filter{root: root}
	filter.flags = filterFlagsOf(root)
	// Compile once at parse time so an expression that is syntactically valid
	// but exceeds the driver's 256-instruction limit fails here, before any
	// native resource exists.
	if _, err = compileTree(root); err != nil {
		return nil, err
	}
	return filter, nil
}

func (p *filterParser) current() filterToken {
	if p.index >= len(p.tokens) {
		return filterToken{kind: tokenEOF}
	}
	return p.tokens[p.index]
}

func (p *filterParser) advance() filterToken {
	token := p.current()
	p.index++
	return token
}

func (p *filterParser) parseOr() (*filterNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		token := p.current()
		if token.kind != tokenIdentifier || token.text != "or" {
			return left, nil
		}
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode(left, right)
	}
}

func (p *filterParser) parseAnd() (*filterNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		token := p.current()
		if token.kind != tokenIdentifier || token.text != "and" {
			return left, nil
		}
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode(left, right)
	}
}

func (p *filterParser) parseUnary() (*filterNode, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > filterMaxDepth {
		return nil, E.New("windivert: filter expression nesting exceeds ", filterMaxDepth)
	}
	token := p.current()
	if token.kind == tokenIdentifier && token.text == "not" {
		p.advance()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode(operand), nil
	}
	if token.kind == tokenOperator && token.text == "!" {
		p.advance()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode(operand), nil
	}
	if token.kind == tokenOperator && token.text == "!=" {
		// `!= value` without a field is not a valid unary operator.
		return nil, E.New("windivert: filter parse error at offset ", token.offset, ": unexpected operator ", strconv.Quote(token.text))
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() (*filterNode, error) {
	token := p.current()
	switch token.kind {
	case tokenLeftParen:
		p.advance()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closing := p.current()
		if closing.kind != tokenRightParen {
			return nil, E.New("windivert: filter parse error at offset ", closing.offset, ": missing ')'")
		}
		p.advance()
		return inner, nil
	case tokenIdentifier:
		switch token.text {
		case "true":
			p.advance()
			return constNode(true), nil
		case "false":
			p.advance()
			return constNode(false), nil
		}
		return p.parseTest()
	case tokenNumber, tokenAddress:
		return nil, E.New("windivert: filter parse error at offset ", token.offset, ": value without a field")
	default:
		return nil, E.New("windivert: filter parse error at offset ", token.offset, ": unexpected token ", strconv.Quote(token.text))
	}
}

func (p *filterParser) parseTest() (*filterNode, error) {
	token := p.advance()
	field, ok := filterFieldByName(token.text)
	if !ok {
		return nil, E.New("windivert: filter parse error at offset ", token.offset, ": unsupported field ", strconv.Quote(token.text))
	}
	operator := p.current()
	if operator.kind != tokenOperator {
		// A boolean field used alone means `field != 0`.
		if !filterFieldIsBoolean(field) {
			return nil, E.New("windivert: filter parse error at offset ", operator.offset, ": field ", strconv.Quote(token.text), " requires a value")
		}
		return booleanNode(field), nil
	}
	p.advance()
	test, ok := filterTestByName(operator.text)
	if !ok {
		return nil, E.New("windivert: filter parse error at offset ", operator.offset, ": unsupported operator ", strconv.Quote(operator.text))
	}
	value := p.current()
	arg, err := filterValueArg(field, value, token.text)
	if err != nil {
		return nil, err
	}
	p.advance()
	return testNode(field, test, arg), nil
}

func filterValueArg(field uint16, token filterToken, fieldName string) ([4]uint32, error) {
	switch field {
	case fieldIPSrcAddr, fieldIPDstAddr:
		if token.kind != tokenAddress || !token.addr.Is4() {
			return [4]uint32{}, E.New("windivert: filter parse error at offset ", token.offset, ": ", fieldName, " requires an IPv4 address")
		}
		return argIPv4(token.addr), nil
	case fieldIPv6SrcAddr, fieldIPv6DstAddr:
		if token.kind != tokenAddress || !token.addr.Is6() || token.addr.Is4() {
			return [4]uint32{}, E.New("windivert: filter parse error at offset ", token.offset, ": ", fieldName, " requires an IPv6 address")
		}
		return argIPv6(token.addr), nil
	}
	if token.kind != tokenNumber {
		return [4]uint32{}, E.New("windivert: filter parse error at offset ", token.offset, ": ", fieldName, " requires a number")
	}
	if token.number > 0xFFFFFFFF {
		return [4]uint32{}, E.New("windivert: filter parse error at offset ", token.offset, ": number out of range")
	}
	if limit, ok := filterFieldMax(field); ok && token.number > uint64(limit) {
		return [4]uint32{}, E.New("windivert: filter parse error at offset ", token.offset, ": ", fieldName, " value out of range")
	}
	return argUint32(uint32(token.number)), nil
}

func filterFieldMax(field uint16) (uint32, bool) {
	switch field {
	case fieldInbound, fieldOutbound, fieldIP, fieldIPv6, fieldTCP, fieldUDP, fieldICMP, fieldICMPv6,
		fieldTCPUrg, fieldTCPAck, fieldTCPPsh, fieldTCPRst, fieldTCPSyn, fieldTCPFin, fieldLoopback, fieldImpostor:
		return 1, true
	case fieldTCPSrcPort, fieldTCPDstPort, fieldUDPSrcPort, fieldUDPDstPort:
		return 0xFFFF, true
	case fieldIfIdx:
		return 0xFFFF, true
	case fieldSubIfIdx:
		return 0xFFFF, true
	}
	return 0, false
}

// filterFlagsOf derives the driver callout flags implied by the fields a
// parsed expression mentions. Flags are OR-ed, never replaced.
func filterFlagsOf(root *filterNode) uint64 {
	var flags uint64
	var walk func(*filterNode)
	walk = func(node *filterNode) {
		if node == nil {
			return
		}
		switch node.kind {
		case nodeAnd, nodeOr:
			walk(node.left)
			walk(node.right)
		case nodeNot:
			walk(node.left)
		case nodeTest:
			switch node.field {
			case fieldInbound:
				flags |= filterFlagInbound
			case fieldOutbound:
				flags |= filterFlagOutbound
			case fieldIP, fieldIPSrcAddr, fieldIPDstAddr:
				flags |= filterFlagIP
			case fieldIPv6, fieldIPv6SrcAddr, fieldIPv6DstAddr:
				flags |= filterFlagIPv6
			}
		}
	}
	walk(root)
	return flags
}

type filterFieldInfo struct {
	id      uint16
	boolean bool
}

// filterFieldNames is the closed set of filter fields this compiler accepts.
// Rejecting unknown fields is deliberate: an unparsed field would either fail
// in the driver with a generic error or, worse, be treated as a different
// field if the id were guessed.
var filterFieldNames = map[string]filterFieldInfo{
	"inbound":           {fieldInbound, true},
	"outbound":          {fieldOutbound, true},
	"ifIdx":             {fieldIfIdx, false},
	"subIfIdx":          {fieldSubIfIdx, false},
	"ip":                {fieldIP, true},
	"ipv6":              {fieldIPv6, true},
	"icmp":              {fieldICMP, true},
	"tcp":               {fieldTCP, true},
	"udp":               {fieldUDP, true},
	"icmpv6":            {fieldICMPv6, true},
	"ip.SrcAddr":        {fieldIPSrcAddr, false},
	"ip.DstAddr":        {fieldIPDstAddr, false},
	"ipv6.SrcAddr":      {fieldIPv6SrcAddr, false},
	"ipv6.DstAddr":      {fieldIPv6DstAddr, false},
	"icmp.Type":         {fieldICMPType, false},
	"icmpv6.Type":       {fieldICMPv6Type, false},
	"tcp.SrcPort":       {fieldTCPSrcPort, false},
	"tcp.DstPort":       {fieldTCPDstPort, false},
	"udp.SrcPort":       {fieldUDPSrcPort, false},
	"udp.DstPort":       {fieldUDPDstPort, false},
	"tcp.Urg":           {fieldTCPUrg, true},
	"tcp.Ack":           {fieldTCPAck, true},
	"tcp.Psh":           {fieldTCPPsh, true},
	"tcp.Rst":           {fieldTCPRst, true},
	"tcp.Syn":           {fieldTCPSyn, true},
	"tcp.Fin":           {fieldTCPFin, true},
	"tcp.PayloadLength": {fieldTCPPayloadLen, false},
	"udp.PayloadLength": {fieldUDPPayloadLen, false},
	"loopback":          {fieldLoopback, true},
	"impostor":          {fieldImpostor, true},
}

func filterFieldByName(name string) (uint16, bool) {
	info, ok := filterFieldNames[name]
	if !ok {
		return 0, false
	}
	return info.id, true
}

func filterFieldIsBoolean(field uint16) bool {
	for _, info := range filterFieldNames {
		if info.id == field {
			return info.boolean
		}
	}
	return false
}

func filterFieldName(field uint16) (string, bool) {
	for name, info := range filterFieldNames {
		if info.id == field {
			return name, true
		}
	}
	return "", false
}

func filterTestByName(operator string) (uint8, bool) {
	switch operator {
	case "==":
		return testEQ, true
	case "!=":
		return testNEQ, true
	case "<":
		return testLT, true
	case "<=":
		return testLEQ, true
	case ">":
		return testGT, true
	case ">=":
		return testGEQ, true
	}
	return 0, false
}

func filterTestOperator(test uint8) (string, bool) {
	switch test {
	case testEQ:
		return "==", true
	case testNEQ:
		return "!=", true
	case testLT:
		return "<", true
	case testLEQ:
		return "<=", true
	case testGT:
		return ">", true
	case testGEQ:
		return ">=", true
	}
	return "", false
}

// MaxFilterExpressionBytes is the bound applied to a single raw filter
// expression (inline or file) before parsing.
func MaxFilterExpressionBytes() int { return filterMaxExpressionBytes }

// InterfaceIndex builds the owned-interface dimension of a capture envelope:
// `ifIdx == index` plus, when sub is non-zero, `subIfIdx == sub`. The caller
// AND-s it with the tuple envelope; it can never widen it.
func InterfaceIndex(index, sub uint32) (*Filter, error) {
	if index > 0xFFFF || sub > 0xFFFF {
		return nil, E.New("windivert: filter: interface index out of range")
	}
	if index == 0 {
		return nil, E.New("windivert: filter: interface index 0 is not a real interface")
	}
	filter := newFilterNode(0)
	filter.add(fieldIfIdx, testEQ, argUint32(index))
	if sub != 0 {
		filter.add(fieldSubIfIdx, testEQ, argUint32(sub))
	}
	return filter, nil
}

// ReadOriginalValue decodes the numeric value of an equality/inequality test
// against a scalar field. It exists for tests and diagnostics; it never
// affects native behaviour.
func ReadOriginalValue(arg [4]uint32) uint32 { return arg[0] }
