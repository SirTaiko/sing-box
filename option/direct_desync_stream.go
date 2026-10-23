package option

import (
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// DirectDesyncStreamRule is one ordered rule of the tpws-equivalent stream
// list `direct.desync.stream_rules`. It is selected independently from the
// packet rules and runs before kernel TCP serialization.
type DirectDesyncStreamRule struct {
	DirectDesyncStreamMatch

	Name     string `json:"name,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`

	// Methods is the ordered tpws method list. The source order of tpws is
	// fixed: the protocol tamper (http_tamper or tls_record) runs before the
	// split/disorder stage. `split` must be listed last.
	Methods badoption.Listable[string] `json:"methods,omitempty" enum:"http_tamper,tls_record,split"`

	HTTPTamper *DirectDesyncStreamHTTPTamper `json:"http_tamper,omitempty"`
	TLSRecord  *DirectDesyncStreamTLSRecord  `json:"tls_record,omitempty"`
	Split      *DirectDesyncStreamSplit      `json:"split,omitempty"`

	// Start and Cutoff use tpws tamper-start/tamper-cutoff spelling
	// `<pos>` or `n<pos>`: a bare number is an outbound stream byte
	// position, `n` selects the 1-based data block number.
	Start  string `json:"start,omitempty"`
	Cutoff string `json:"cutoff,omitempty"`

	// MSS maps tpws `--mss`: set the client MSS before connect so the server
	// splits messages. The accepted range is the upstream one, 88..32767.
	// Implemented on Linux only (TCP_MAXSEG); other platforms reject it
	// instead of silently ignoring it.
	MSS int `json:"mss,omitempty"`
	// SkipNoDelay maps tpws `--skip-nodelay`: do not force TCP_NODELAY and do
	// not cork/TTL-shape stream sends. Incompatible with split, as upstream.
	SkipNoDelay bool `json:"skip_nodelay,omitempty"`
	// FixSeg maps tpws `--fix-seg`: wait up to this many milliseconds for
	// the previous split fragment to leave the kernel send queue before
	// sending the next one. `true` is the bare upstream flag and means the
	// upstream default of 50 ms, while an explicit 0 only inspects the queue
	// once without waiting. Absent disables the wait. Linux only (TCP_INFO
	// tcpi_notsent_bytes).
	FixSeg *DirectDesyncStreamFixSeg `json:"fix_seg,omitempty"`

	// Learning enables the upstream tpws auto-hostlist behaviour for this
	// stream rule: the first HTTP reply observed on the connection counts as
	// a success (counter reset) or, for a cross-domain redirect, as a failure.
	// Thresholds are the shared DirectDesyncRuleLearning fields and the store
	// is the same per-outbound `desync.learning` owner as the packet rules.
	// `retrans_threshold` is accepted for type compatibility but intentionally
	// has no effect: tpws has no TCP retransmission learning, and inventing
	// packet-level retransmission counting for a stream rule would not be
	// source-faithful.
	Learning *DirectDesyncRuleLearning `json:"learning,omitempty"`
}

// DirectDesyncStreamFixSeg is the tpws `--fix-seg` value. tpws has two distinct
// spellings that must not collapse into one number: a bare `--fix-seg` uses
// FIX_SEG_DEFAULT_MAX_WAIT (50 ms), while `--fix-seg=0` is an explicit zero
// that only inspects the send queue once. In JSON the bare form is `true`.
type DirectDesyncStreamFixSeg struct {
	// Default selects the upstream 50 ms default of a bare --fix-seg.
	Default bool
	// Milliseconds is the explicit --fix-seg=N value, 0..1000.
	Milliseconds int
}

func (v *DirectDesyncStreamFixSeg) UnmarshalJSON(content []byte) error {
	if len(content) == 0 {
		return E.New("empty fix_seg")
	}
	switch content[0] {
	case 't', 'f':
		var enabled bool
		if err := json.Unmarshal(content, &enabled); err != nil {
			return E.Cause(err, "invalid fix_seg")
		}
		if !enabled {
			return E.New("fix_seg must be true (upstream default) or 0..1000 milliseconds")
		}
		*v = DirectDesyncStreamFixSeg{Default: true}
		return nil
	}
	var milliseconds int
	if err := json.Unmarshal(content, &milliseconds); err != nil {
		return E.Cause(err, "fix_seg must be true (upstream default) or 0..1000 milliseconds")
	}
	*v = DirectDesyncStreamFixSeg{Milliseconds: milliseconds}
	return nil
}

func (v DirectDesyncStreamFixSeg) MarshalJSON() ([]byte, error) {
	if v.Default {
		return []byte("true"), nil
	}
	return json.Marshal(v.Milliseconds)
}

// DirectDesyncStreamMatch uses the same spelling and semantics as the packet
// rule matcher. The stream transport is TCP by construction; a `udp` entry is
// rejected instead of being accepted as a no-op.
type DirectDesyncStreamMatch struct {
	Network   badoption.Listable[string] `json:"network,omitempty" enum:"tcp"`
	IPVersion badoption.Listable[int]    `json:"ip_version,omitempty"`

	Port              badoption.Listable[uint16] `json:"port,omitempty"`
	PortRange         badoption.Listable[string] `json:"port_range,omitempty"`
	PortExclude       badoption.Listable[uint16] `json:"port_exclude,omitempty"`
	PortRangeExclude  badoption.Listable[string] `json:"port_range_exclude,omitempty"`
	Protocol          badoption.Listable[string] `json:"protocol,omitempty"`
	Domain            badoption.Listable[string] `json:"domain,omitempty"`
	DomainFile        badoption.Listable[string] `json:"domain_file,omitempty"`
	DomainExclude     badoption.Listable[string] `json:"domain_exclude,omitempty"`
	DomainExcludeFile badoption.Listable[string] `json:"domain_exclude_file,omitempty"`
	IPCIDR            badoption.Listable[string] `json:"ip_cidr,omitempty"`
	IPCIDRFile        badoption.Listable[string] `json:"ip_cidr_file,omitempty"`
	IPCIDRExclude     badoption.Listable[string] `json:"ip_cidr_exclude,omitempty"`
	IPCIDRExcludeFile badoption.Listable[string] `json:"ip_cidr_exclude_file,omitempty"`

	// ListBundle selects immutable datasets of a provider list bundle for
	// this stream match. It is the same reusable option type as the packet
	// rule and is additive with the inline/file fields.
	ListBundle *DirectDesyncListBundle `json:"list_bundle,omitempty"`
}

// DirectDesyncStreamHTTPTamper maps the tpws HTTP tamper flags. Every field is
// an intentional representation change of the outbound request bytes.
type DirectDesyncStreamHTTPTamper struct {
	// HostCase maps `--hostcase`: rewrite the Host header name to HostSpell.
	HostCase bool `json:"hostcase,omitempty"`
	// HostSpell maps `--hostspell`: exact 4-byte Host header spelling. It
	// implies hostcase, as upstream.
	HostSpell string `json:"hostspell,omitempty"`
	// HostDot maps `--hostdot`: insert '.' at the end of the host value.
	HostDot bool `json:"hostdot,omitempty"`
	// HostTab maps `--hosttab`: insert a tab at the end of the host value.
	HostTab bool `json:"hosttab,omitempty"`
	// HostNoSpace maps `--hostnospace`: remove the space after `Host:`.
	HostNoSpace bool `json:"hostnospace,omitempty"`
	// HostPad maps `--hostpad`: insert at least this many bytes of dummy
	// header lines before the Host header.
	HostPad int `json:"hostpad,omitempty"`
	// DomCase maps `--domcase`: alternate upper/lower case over the host
	// value. Upstream derives the phase from pointer parity; the block offset
	// is the deterministic equivalent for an aligned receive block.
	DomCase bool `json:"domcase,omitempty"`
	// MethodSpace maps `--methodspace`: insert an extra space after the
	// request method.
	MethodSpace bool `json:"methodspace,omitempty"`
	// MethodEOL maps `--methodeol`: insert an end of line before the method.
	MethodEOL bool `json:"methodeol,omitempty"`
	// UnixEOL maps `--unixeol`: replace CRLF with LF up to and including the
	// end of the header block.
	UnixEOL bool `json:"unixeol,omitempty"`
}

// DirectDesyncStreamTLSRecord maps tpws `--tlsrec`: split the first TLS
// record of a ClientHello into two records at Pos. `TLSRecordPos` (upstream
// `tlsrec-pos`) is the deprecated numeric alias.
type DirectDesyncStreamTLSRecord struct {
	// Pos accepts N, -N, marker, marker±N with markers
	// host,endhost,sld,endsld,midsld,sniext plus deprecated tpws aliases
	// sni (= host+1) and snisld (= midsld).
	Pos string `json:"pos,omitempty"`
	// RecordPos is the deprecated numeric `--tlsrec-pos` spelling.
	RecordPos int `json:"record_pos,omitempty"`
}

// DirectDesyncStreamSplit maps tpws split/disorder/OOB stream behavior.
type DirectDesyncStreamSplit struct {
	// SplitPos maps `--split-pos=N|-N|marker±N,...`.
	SplitPos badoption.Listable[string] `json:"split_pos,omitempty"`
	// SplitHTTPReq maps deprecated `--split-http-req=method|host`.
	SplitHTTPReq string `json:"split_http_req,omitempty" enum:"method,host,"`
	// SplitTLS maps deprecated `--split-tls=sni|sniext|snisld`.
	SplitTLS string `json:"split_tls,omitempty" enum:"sni,sniext,snisld,"`

	// Disorder maps `--disorder[=http|tls]`: send even fragments with a low
	// TTL so native TCP retransmission reorders them. `any` is the bare
	// upstream form.
	Disorder string `json:"disorder,omitempty" enum:"any,http,tls,"`
	// OOB maps `--oob[=http|tls]`: send one out-of-band byte with the first
	// fragment.
	OOB string `json:"oob,omitempty" enum:"any,http,tls,"`
	// OOBData maps `--oob-data=<char>|0xHH`. Absent means 0x00.
	OOBData *DirectDesyncOOBByte `json:"oob_data,omitempty"`
	// SplitAnyProtocol maps `--split-any-protocol`: resolve absolute split
	// positions for protocols other than HTTP/TLS.
	SplitAnyProtocol bool `json:"split_any_protocol,omitempty"`
}

// DirectDesyncOOBByte is a single out-of-band byte: one literal character or
// `0xHH`, exactly as tpws accepts.
type DirectDesyncOOBByte struct {
	Value byte
}

func (v *DirectDesyncOOBByte) UnmarshalJSON(content []byte) error {
	if len(content) == 0 {
		return E.New("empty oob_data")
	}
	if content[0] != '"' {
		return E.New("oob_data must be a quoted character or 0xHH")
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return E.Cause(err, "invalid oob_data")
	}
	switch len(value) {
	case 1:
		v.Value = value[0]
		return nil
	case 4:
		if value[0] != '0' || (value[1] != 'x' && value[1] != 'X') {
			return E.New("invalid oob_data ", strconv.Quote(value))
		}
		parsed, err := strconv.ParseUint(value[2:], 16, 8)
		if err != nil {
			return E.Cause(err, "invalid oob_data ", strconv.Quote(value))
		}
		v.Value = byte(parsed)
		return nil
	default:
		return E.New("oob_data must be one character or 0xHH")
	}
}

func (v DirectDesyncOOBByte) MarshalJSON() ([]byte, error) {
	return json.Marshal(string([]byte{v.Value}))
}
