package desync

// D3 native capture selectors owned by one per-outbound engine.
//
// U1 placement: the portable capture policy (tcp_empty_ack) stays on
// option.DirectDesyncCapture; OS-specific controls live only under
// capture.linux / capture.windows. This file holds the Linux subset that is
// implemented natively in this increment:
//
//   - qnum: explicit NFQUEUE identity override. Upstream accepts 0..65535
//     (`nfqws.c` IDX_QNUM) and requires the queue to be bindable. An explicit
//     identity is never silently replaced: it must be free in the kernel
//     report, outside the managed allocation window, and unique among this
//     process's live captures.
//   - fwmark: additional mark of generated packets (`desync_fwmark` in
//     `nfq/desync.c`), OR-ed into the routing mark owned by the dialer. The
//     dialer's mark bits are never cleared or replaced.
//   - bind_fix4 / bind_fix6: upstream `--bind-fix4/--bind-fix6`
//     (`rawsend_preinit`), i.e. bind the injection socket to the source
//     address of the generated packet and to the owned output device. The
//     socket keeps sending when the bind is refused, exactly like upstream
//     ("bind (ignoring)").
//
// Windows-only rows (wf-iface/wf-l3/wf-tcp/wf-udp/wf-raw/wf-raw-part/
// filter-lan/filter-save and SSID/NLM activation) are not represented here:
// they need a real native data path, and a schema without it would be a stub.

import (
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/option"
)

// Managed NFQUEUE allocation window shared by every engine of this process.
// Identities below the base belong to the host and are never probed.
const (
	managedQueueBase = 1024
	managedQueueSpan = 48000
)

// captureSelector is the portable capture narrowing: transport, family and
// port predicates intersected with the owned tuple. An absent selector matches
// everything the owned socket carries.
type captureSelector struct {
	network TransportMask
	ipv4    bool
	ipv6    bool
	ports   []PortRange
	exclude []PortRange
}

// allows reports whether an owned flow packet is inside both the selector and
// the ownership envelope. The caller always applies it to an already owned
// tuple; it can only narrow.
func (s captureSelector) allows(family Family, transport Transport, port uint16) bool {
	if s.network != 0 {
		if transport == TransportTCP && s.network&TransportMaskTCP == 0 {
			return false
		}
		if transport == TransportUDP && s.network&TransportMaskUDP == 0 {
			return false
		}
	}
	// A zero selector has no family bits: it is unrestricted, so a
	// configuration without capture selectors behaves exactly as before.
	if s.ipv4 || s.ipv6 {
		if family == FamilyIPv4 && !s.ipv4 {
			return false
		}
		if family == FamilyIPv6 && !s.ipv6 {
			return false
		}
	}
	if len(s.ports) > 0 {
		matched := false
		for _, portRange := range s.ports {
			if portRange.Contains(port) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, portRange := range s.exclude {
		if portRange.Contains(port) {
			return false
		}
	}
	return true
}

// allowsEndpoint applies the selector to the owned native attempt. Listener
// ownership (no destination) is judged on the local port.
func (s captureSelector) allowsEndpoint(endpoint Endpoint) bool {
	port := endpoint.Destination.Port()
	if !endpoint.Destination.IsValid() {
		port = endpoint.Source.Port()
	}
	return s.allows(endpoint.Family, endpoint.Transport, port)
}

// captureConfig is the compiled OS-specific capture narrowing of one outbound.
type captureConfig struct {
	qnum    int
	qnumSet bool

	selectors captureSelector

	fwmark    uint32
	fwmarkSet bool

	bindFix4 bool
	bindFix6 bool

	// limits is the compiled capture.linux.packet_limits set: the upstream
	// NFQWS_*_PKT_* inclusive kernel conntrack bound per transport/direction.
	limits packetLimits
	// keepalive is the compiled capture.linux.*_keepalive_port_range set:
	// destination ports whose outgoing packet bound is removed.
	keepalive packetKeepalive

	// filterTTLExpiredICMP is capture.filter_ttl_expired_icmp: whether validated
	// quoted time-exceeded errors of this lease's own low-hop packets are
	// suppressed. Default false (upstream FILTER_TTL_EXPIRED_ICMP).
	filterTTLExpiredICMP bool

	// windows is the compiled capture.windows narrowing. It is nil when the
	// configuration carries no Windows capture block.
	windows *windowsCaptureConfig
}

// packetLimit is one direction-specific NFQWS_*_PKT_* bound. An unset limit is
// unlimited capture (the previous behavior), an explicit zero disables capture
// of that direction, and a positive value keeps the first N packets exactly as
// the source `1-N` kernel conntrack range does.
type packetLimit struct {
	value int
	set   bool
}

// enabled reports whether the direction is captured at all.
func (l packetLimit) enabled() bool { return !l.set || l.value > 0 }

// bounded reports whether the rule must carry the kernel packet counter test.
func (l packetLimit) bounded() bool { return l.set && l.value > 0 }

type packetLimits struct {
	tcpOut packetLimit
	tcpIn  packetLimit
	udpOut packetLimit
	udpIn  packetLimit
}

func (l packetLimits) direction(transport Transport, outbound bool) packetLimit {
	switch transport {
	case TransportTCP:
		if outbound {
			return l.tcpOut
		}
		return l.tcpIn
	case TransportUDP:
		if outbound {
			return l.udpOut
		}
		return l.udpIn
	}
	return packetLimit{}
}

// packetKeepalive is the compiled NFQWS_PORTS_*_KEEPALIVE destination-port
// set. Like the source, a keepalive port removes only the outgoing bound.
type packetKeepalive struct {
	tcp []PortRange
	udp []PortRange
}

func (k packetKeepalive) contains(transport Transport, port uint16) bool {
	var ranges []PortRange
	switch transport {
	case TransportTCP:
		ranges = k.tcp
	case TransportUDP:
		ranges = k.udp
	default:
		return false
	}
	for _, portRange := range ranges {
		if portRange.Contains(port) {
			return true
		}
	}
	return false
}

// compilePortRanges parses the existing range grammar used by the capture
// selectors. It is shared with the keepalive port sets so there is exactly one
// accepted spelling of a port range.
func compilePortRanges(values []string) ([]PortRange, error) {
	if len(values) == 0 {
		return nil, nil
	}
	ranges := make([]PortRange, 0, len(values))
	for _, value := range values {
		parsed, err := parsePortRange(value)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, parsed)
	}
	return ranges, nil
}

// bindSource reports whether the upstream bind-fix applies to a generated
// packet of this family (rawsend_preinit / rawsend in nfq/darkmagic.c).
func bindSource(capture captureConfig, family Family) bool {
	switch family {
	case FamilyIPv4:
		return capture.bindFix4
	case FamilyIPv6:
		return capture.bindFix6
	}
	return false
}

// injectionMark returns the mark of a generated packet: the routing mark
// inherited from the owned socket with the configured desync mark OR-ed in.
// No bit of the dialer-owned mark is cleared.
func injectionMark(base int, capture captureConfig) int {
	mark := base
	if capture.fwmarkSet {
		mark |= int(capture.fwmark)
	}
	return mark
}

// validateQnum applies the upstream qnum range (nfqws.c IDX_QNUM). Explicit
// identities are legal anywhere in 0..65535, including the managed window; the
// allocator avoids live reservations through the in-process registry.
func validateQnum(qnum int) error {
	if qnum < 0 || qnum > 65535 {
		return fmt.Errorf("desync: capture.linux.qnum %d outside 0..65535", qnum)
	}
	return nil
}

// qnumLive reports whether this process already reserved the identity.
func qnumLive(qnum int) bool {
	qnumRegistry.mu.Lock()
	defer qnumRegistry.mu.Unlock()
	_, found := qnumRegistry.live[qnum]
	return found
}

// qnumRegistry enforces uniqueness of explicit queue identities among live
// captures of this process. It never touches the kernel or another process.
var qnumRegistry = struct {
	mu   sync.Mutex
	live map[int]int
}{live: make(map[int]int)}

// reserveQnum registers an explicit identity for one capture. A second live
// capture with the same identity is a configuration collision, not a fallback.
func reserveQnum(qnum int) error {
	qnumRegistry.mu.Lock()
	defer qnumRegistry.mu.Unlock()
	if _, found := qnumRegistry.live[qnum]; found {
		return fmt.Errorf("desync: capture.linux.qnum %d already owned by a live capture", qnum)
	}
	qnumRegistry.live[qnum] = qnum
	return nil
}

func releaseQnum(qnum int) {
	qnumRegistry.mu.Lock()
	delete(qnumRegistry.live, qnum)
	qnumRegistry.mu.Unlock()
}

// compileNativeCapture validates capture.linux and produces the per-outbound
// narrowing. Configuration compilation is read-only: no queue is probed and no
// file or socket is touched here.
func compileNativeCapture(source *option.DirectDesyncCapture) (captureConfig, error) {
	capture := captureConfig{selectors: captureSelector{ipv4: true, ipv6: true}}
	if source == nil {
		return capture, nil
	}
	if source.FilterTTLExpiredICMP != nil {
		capture.filterTTLExpiredICMP = *source.FilterTTLExpiredICMP
	}
	for _, network := range source.Network {
		switch network {
		case "tcp":
			capture.selectors.network |= TransportMaskTCP
		case "udp":
			capture.selectors.network |= TransportMaskUDP
		default:
			return capture, fmt.Errorf("desync: capture.network %q is not tcp or udp", network)
		}
	}
	if len(source.IPVersion) > 0 {
		capture.selectors.ipv4, capture.selectors.ipv6 = false, false
		for _, version := range source.IPVersion {
			switch version {
			case 4:
				capture.selectors.ipv4 = true
			case 6:
				capture.selectors.ipv6 = true
			default:
				return capture, fmt.Errorf("desync: capture.ip_version %d is not 4 or 6", version)
			}
		}
	}
	for _, port := range source.Port {
		capture.selectors.ports = append(capture.selectors.ports, PortRange{From: port, To: port})
	}
	for _, value := range source.PortRange {
		parsed, err := parsePortRange(value)
		if err != nil {
			return capture, err
		}
		capture.selectors.ports = append(capture.selectors.ports, parsed)
	}
	for _, port := range source.PortExclude {
		capture.selectors.exclude = append(capture.selectors.exclude, PortRange{From: port, To: port})
	}
	for _, value := range source.PortRangeExclude {
		parsed, err := parsePortRange(value)
		if err != nil {
			return capture, err
		}
		capture.selectors.exclude = append(capture.selectors.exclude, parsed)
	}
	linux := source.Linux
	if linux != nil {
		if linux.Qnum != nil {
			if err := validateQnum(*linux.Qnum); err != nil {
				return capture, err
			}
			capture.qnum, capture.qnumSet = *linux.Qnum, true
		}
		if linux.Fwmark != nil {
			capture.fwmark, capture.fwmarkSet = *linux.Fwmark, true
		}
		if linux.BindFix4 != nil {
			capture.bindFix4 = *linux.BindFix4
		}
		if linux.BindFix6 != nil {
			capture.bindFix6 = *linux.BindFix6
		}
		if limits := linux.PacketLimits; limits != nil {
			for _, field := range []struct {
				name    string
				value   *int
				limit   *packetLimit
				inbound bool
			}{
				{"tcp_out", limits.TCPOut, &capture.limits.tcpOut, false},
				{"tcp_in", limits.TCPIn, &capture.limits.tcpIn, true},
				{"udp_out", limits.UDPOut, &capture.limits.udpOut, false},
				{"udp_in", limits.UDPIn, &capture.limits.udpIn, true},
			} {
				if field.value == nil {
					continue
				}
				if *field.value < 0 {
					return capture, fmt.Errorf("desync: capture.linux.packet_limits.%s must be nonnegative", field.name)
				}
				field.limit.value, field.limit.set = *field.value, true
			}
		}
		tcpKeepalive, err := compilePortRanges(linux.TCPKeepalivePortRange)
		if err != nil {
			return capture, fmt.Errorf("desync: capture.linux.tcp_keepalive_port_range: %w", err)
		}
		udpKeepalive, err := compilePortRanges(linux.UDPKeepalivePortRange)
		if err != nil {
			return capture, fmt.Errorf("desync: capture.linux.udp_keepalive_port_range: %w", err)
		}
		capture.keepalive.tcp = tcpKeepalive
		capture.keepalive.udp = udpKeepalive
	}
	windowsCapture, err := compileWindowsCapture(source.Windows)
	if err != nil {
		return capture, err
	}
	capture.windows = windowsCapture
	return capture, nil
}
