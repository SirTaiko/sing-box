package desync

// D3 Windows capture narrowing: typed capture.windows controls, the owned
// capture filter composition, and the WLAN SSID / NLM network activation gate.
//
// Source: bol-van/zapret v72.9 c849e55e, nfq/nfqws.c (wf_make_filter,
// wf_make_pf, wf_make_l3, IDX_WF_IFACE/IDX_WF_L3/IDX_WF_TCP/IDX_WF_UDP/
// IDX_WF_RAW/IDX_WF_RAW_PART/IDX_WF_FILTER_LAN/IDX_WF_SAVE) and nfq/darkmagic.c
// (wlan_filter_match, nlm_filter_match, logical_net_filter_match).
//
// U1 placement: every field narrows the already owned native attempt. The
// composed kernel filter is ALWAYS
//
//	owned envelope (direction + family + tuple + owned interface index)
//	AND ( <user expression> )
//	[AND (non-LAN address exclusion)]
//
// so no user expression — including one made only of `or`/`not` — can widen
// capture beyond the owned socket. The user expression is parsed and compiled
// by common/windivert; an unparsable or unsupported expression is an explicit
// configuration error, never a blob forwarded to the driver.

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/windivert"
	"github.com/sagernet/sing-box/option"
)

// windowsCaptureConfig is the compiled capture.windows narrowing.
type windowsCaptureConfig struct {
	ifaceSet bool
	iface    uint32
	subIfIdx uint32

	l3v4 bool
	l3v6 bool

	tcpPorts *wfPortFilter
	udpPorts *wfPortFilter

	// raw is the full raw filter that replaces wf_tcp/wf_udp/wf_raw_part.
	rawText string
	// rawParts are partial raw filters OR-ed together, exactly like upstream.
	rawParts []string

	filterLAN bool

	filterSave string

	ssidFilter []string
	nlmFilter  []string
}

// wfPortFilter is one parsed --wf-tcp/--wf-udp list.
type wfPortFilter struct {
	items []wfPortItem
}

type wfPortItem struct {
	from uint16
	to   uint16
	neg  bool
}

// allows applies the upstream port filter to one port.
func (f *wfPortFilter) allows(port uint16) bool {
	if f == nil {
		return true
	}
	matched := false
	for _, item := range f.items {
		inside := port >= item.from && port <= item.to
		if item.neg {
			// A negated item excludes the port outright, matching the
			// upstream `!=`/`< or >` clause.
			if inside {
				return false
			}
			continue
		}
		if inside {
			matched = true
		}
	}
	if len(f.items) == 0 {
		return false
	}
	hasPositive := false
	for _, item := range f.items {
		if !item.neg {
			hasPositive = true
			break
		}
	}
	if !hasPositive {
		// A list containing only negations matches everything except those
		// ports, exactly like the upstream clause `port != x`.
		return true
	}
	return matched
}

// validate compiles capture.windows. It is read-only: no file is written, no
// adapter is queried and no handle is opened.
func compileWindowsCapture(source *option.DirectDesyncCaptureWindows) (*windowsCaptureConfig, error) {
	if source == nil {
		return nil, nil
	}
	capture := &windowsCaptureConfig{l3v4: true, l3v6: true, filterLAN: true}
	if source.WFIface != "" {
		ifIndex, subIfIdx, err := parseWFIface(source.WFIface)
		if err != nil {
			return nil, err
		}
		capture.ifaceSet, capture.iface, capture.subIfIdx = true, ifIndex, subIfIdx
	}
	if len(source.WFL3) > 0 {
		capture.l3v4, capture.l3v6 = false, false
		for _, value := range source.WFL3 {
			switch strings.TrimSpace(value) {
			case "ipv4":
				capture.l3v4 = true
			case "ipv6":
				capture.l3v6 = true
			default:
				return nil, fmt.Errorf("desync: capture.windows.wf_l3 %q is not ipv4 or ipv6", value)
			}
		}
	}
	if len(source.WFTCP) > 0 {
		parsed, err := compileWFPortFilter(source.WFTCP)
		if err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_tcp: %w", err)
		}
		capture.tcpPorts = parsed
	}
	if len(source.WFUDP) > 0 {
		parsed, err := compileWFPortFilter(source.WFUDP)
		if err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_udp: %w", err)
		}
		capture.udpPorts = parsed
	}
	if source.WFRaw != "" {
		// Upstream: --wf-raw replaces --wf-tcp, --wf-udp and --wf-raw-part.
		// Silently ignoring the other selectors would hide an operator error,
		// so a conflict is refused instead.
		if len(source.WFTCP) > 0 || len(source.WFUDP) > 0 || len(source.WFRawPart) > 0 {
			return nil, fmt.Errorf("desync: capture.windows.wf_raw replaces wf_tcp/wf_udp/wf_raw_part; remove the other selectors")
		}
		expression, err := readFilterExpression(source.WFRaw)
		if err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_raw: %w", err)
		}
		// Validate now, at configuration compilation, so an unparsable
		// expression fails before any native resource exists.
		if _, err = windivert.ParseFilter(expression); err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_raw: %w", err)
		}
		capture.rawText = expression
	}
	for _, value := range source.WFRawPart {
		expression, err := readFilterExpression(value)
		if err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_raw_part: %w", err)
		}
		if _, err = windivert.ParseFilter(expression); err != nil {
			return nil, fmt.Errorf("desync: capture.windows.wf_raw_part: %w", err)
		}
		capture.rawParts = append(capture.rawParts, expression)
	}
	if source.FilterLAN != nil {
		capture.filterLAN = *source.FilterLAN
	}
	if source.FilterSave != "" {
		if len(source.FilterSave) > maxFilterSavePath {
			return nil, fmt.Errorf("desync: capture.windows.filter_save path is longer than %d bytes", maxFilterSavePath)
		}
		if strings.ContainsRune(source.FilterSave, 0) {
			return nil, fmt.Errorf("desync: capture.windows.filter_save path contains NUL")
		}
		capture.filterSave = source.FilterSave
	}
	for _, ssid := range source.SSIDFilter {
		if ssid == "" {
			return nil, fmt.Errorf("desync: capture.windows.ssid_filter contains an empty SSID")
		}
		capture.ssidFilter = append(capture.ssidFilter, ssid)
	}
	for _, network := range source.NLMFilter {
		if network == "" {
			return nil, fmt.Errorf("desync: capture.windows.nlm_filter contains an empty network")
		}
		if len(network) == 36 {
			if _, err := parseGUID(network); err != nil {
				return nil, fmt.Errorf("desync: capture.windows.nlm_filter %q: %w", network, err)
			}
		}
		capture.nlmFilter = append(capture.nlmFilter, network)
	}
	return capture, nil
}

const maxFilterSavePath = 512

// readFilterExpression accepts an inline expression or the upstream
// `@<filename>` form. The file read is bounded and happens at configuration
// compilation; it is a read, never a write.
func readFilterExpression(value string) (string, error) {
	if !strings.HasPrefix(value, "@") {
		return strings.TrimSpace(value), nil
	}
	path := strings.TrimPrefix(value, "@")
	if path == "" {
		return "", fmt.Errorf("empty filter file name")
	}
	data, err := readBoundedFile(path, windivert.MaxFilterExpressionBytes())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// parseWFIface parses the upstream `--wf-iface=<int>[.<int>]` form. Upstream
// uses sscanf("%u.%u"); a missing subinterface is 0.
func parseWFIface(value string) (uint32, uint32, error) {
	ifIndexText, subIfIdxText, hasSub := strings.Cut(strings.TrimSpace(value), ".")
	ifIndex, err := strconv.ParseUint(strings.TrimSpace(ifIndexText), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("desync: capture.windows.wf_iface %q: invalid interface index", value)
	}
	subIfIdx := uint64(0)
	if hasSub {
		subIfIdx, err = strconv.ParseUint(strings.TrimSpace(subIfIdxText), 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("desync: capture.windows.wf_iface %q: invalid subinterface index", value)
		}
	}
	if ifIndex > 0xFFFF || subIfIdx > 0xFFFF {
		return 0, 0, fmt.Errorf("desync: capture.windows.wf_iface %q is outside the 16-bit interface range", value)
	}
	return uint32(ifIndex), uint32(subIfIdx), nil
}

// compileWFPortFilter parses the upstream `[~]port1[-port2]` comma list. The
// JSON schema already splits on commas, but an entry may still carry a comma
// separated list to mirror the upstream command line exactly.
func compileWFPortFilter(entries []string) (*wfPortFilter, error) {
	filter := &wfPortFilter{}
	for _, entry := range entries {
		for _, item := range strings.Split(entry, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, fmt.Errorf("empty port filter entry")
			}
			neg := strings.HasPrefix(item, "~")
			if neg {
				item = strings.TrimPrefix(item, "~")
			}
			fromText, toText, hasRange := strings.Cut(item, "-")
			from, err := parseWFPort(fromText)
			if err != nil {
				return nil, err
			}
			to := from
			if hasRange {
				to, err = parseWFPort(toText)
				if err != nil {
					return nil, err
				}
				if to < from {
					return nil, fmt.Errorf("port range %q is reversed", item)
				}
			}
			filter.items = append(filter.items, wfPortItem{from: from, to: to, neg: neg})
		}
	}
	if len(filter.items) == 0 {
		return nil, fmt.Errorf("no port filter entries")
	}
	return filter, nil
}

func parseWFPort(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port == 0 {
		return 0, fmt.Errorf("port 0 is not capturable")
	}
	return uint16(port), nil
}

// excludesOwnedEndpoint reports whether the structured capture.windows
// narrowing provably excludes the owned native attempt. Raw expressions are
// not evaluated here; they are compiled and AND-ed with the envelope, so they
// can only narrow at packet time.
func (c *windowsCaptureConfig) excludesOwnedEndpoint(endpoint Endpoint) error {
	if c == nil {
		return nil
	}
	if endpoint.Family == FamilyIPv4 && !c.l3v4 {
		return fmt.Errorf("desync: capture.windows.wf_l3 excludes the owned IPv4 attempt")
	}
	if endpoint.Family == FamilyIPv6 && !c.l3v6 {
		return fmt.Errorf("desync: capture.windows.wf_l3 excludes the owned IPv6 attempt")
	}
	if c.ifaceSet && endpoint.InterfaceIndex != 0 && endpoint.InterfaceIndex != c.iface {
		return fmt.Errorf("desync: capture.windows.wf_iface %d excludes the owned attempt interface %d",
			c.iface, endpoint.InterfaceIndex)
	}
	if c.rawText != "" {
		return nil
	}
	// Omitted wf_tcp/wf_udp is the upstream "no port clause" form: the driver
	// filter then carries no transport-port narrowing at all, so a non-port
	// selector (wf_iface, wf_l3, filter_lan, wf_raw_part) must not erase the
	// default admission of an owned attempt. Only a configured port list
	// restricts transports, and then the missing protocol is a real
	// restriction: upstream ORs the configured tcp/udp clauses, so an
	// unlisted transport is not captured.
	transportNarrowed := c.tcpPorts != nil || c.udpPorts != nil
	if endpoint.Destination.IsValid() {
		switch endpoint.Transport {
		case TransportTCP:
			if c.tcpPorts == nil {
				if transportNarrowed {
					return fmt.Errorf("desync: capture.windows excludes the owned TCP attempt (wf_tcp is not configured)")
				}
				return nil
			}
			if !c.tcpPorts.allows(endpoint.Destination.Port()) {
				return fmt.Errorf("desync: capture.windows.wf_tcp excludes the owned TCP port %d", endpoint.Destination.Port())
			}
		case TransportUDP:
			if c.udpPorts == nil {
				if transportNarrowed {
					return fmt.Errorf("desync: capture.windows excludes the owned UDP attempt (wf_udp is not configured)")
				}
				return nil
			}
			if !c.udpPorts.allows(endpoint.Destination.Port()) {
				return fmt.Errorf("desync: capture.windows.wf_udp excludes the owned UDP port %d", endpoint.Destination.Port())
			}
		}
	}
	return nil
}

// envelope builds the owned kernel filter for one direction. The envelope is
// authoritative: direction, family, exact tuple and the owned interface index
// are always present. Both capture paths share ownedWindowsEnvelope, so the
// configured path cannot widen or narrow the plain one.
func (c *windowsCaptureConfig) envelope(endpoint Endpoint, outbound bool) (*windivert.Filter, error) {
	return ownedWindowsEnvelope(endpoint, outbound)
}

// userExpression renders the operator expression for one direction. It is
// always wrapped in its own parentheses by the compiler and is AND-ed with the
// envelope, so internal `or`/`not` can never escape ownership.
func (c *windowsCaptureConfig) userExpression(endpoint Endpoint, outbound bool) (string, error) {
	if c.rawText != "" {
		return c.rawText, nil
	}
	var terms []string
	port := endpoint.Destination.Port()
	if !endpoint.Destination.IsValid() {
		port = endpoint.Source.Port()
	}
	if endpoint.Transport == TransportTCP && c.tcpPorts != nil {
		terms = append(terms, "tcp and "+renderWFPortFilter("tcp", outbound, c.tcpPorts, port))
	}
	if endpoint.Transport == TransportUDP && c.udpPorts != nil {
		terms = append(terms, "udp and "+renderWFPortFilter("udp", outbound, c.udpPorts, port))
	}
	terms = append(terms, c.rawParts...)
	if len(terms) == 0 {
		return "", nil
	}
	return "(" + strings.Join(terms, ") or (") + ")", nil
}

// renderWFPortFilter renders the upstream wf_make_pf clause for one direction.
func renderWFPortFilter(transport string, outbound bool, filter *wfPortFilter, _ uint16) string {
	portName := "SrcPort"
	if outbound {
		portName = "DstPort"
	}
	parts := make([]string, 0, len(filter.items))
	for _, item := range filter.items {
		field := transport + "." + portName
		switch {
		case item.from == item.to && item.neg:
			parts = append(parts, fmt.Sprintf("%s != %d", field, item.from))
		case item.from == item.to:
			parts = append(parts, fmt.Sprintf("%s == %d", field, item.from))
		case item.neg:
			parts = append(parts, fmt.Sprintf("(%s < %d or %s > %d)", field, item.from, field, item.to))
		default:
			parts = append(parts, fmt.Sprintf("(%s >= %d and %s <= %d)", field, item.from, field, item.to))
		}
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// lanExpression renders the upstream non-global address exclusion. The
// direction-specific branch of the upstream macro is used because the owned
// envelope already pins the direction.
func (c *windowsCaptureConfig) lanExpression(endpoint Endpoint, outbound bool) string {
	if !c.filterLAN {
		return ""
	}
	direction := "Dst"
	if !outbound {
		direction = "Src"
	}
	if endpoint.Family == FamilyIPv6 {
		field := "ipv6." + direction + "Addr"
		return "(" + strings.Join([]string{
			fmt.Sprintf("(%s > ::1)", field),
			fmt.Sprintf("(%s < 2001::0 or %s >= 2001:1::0)", field, field),
			fmt.Sprintf("(%s < fc00::0 or %s >= fe00::0)", field, field),
			fmt.Sprintf("(%s < fe80::0 or %s >= fec0::0)", field, field),
			fmt.Sprintf("(%s < ff00::0 or %s >= ffff::0)", field, field),
		}, " and ") + ")"
	}
	field := "ip." + direction + "Addr"
	ranges := [][2]string{
		{"127.0.0.1", "127.255.255.255"},
		{"10.0.0.0", "10.255.255.255"},
		{"192.168.0.0", "192.168.255.255"},
		{"172.16.0.0", "172.31.255.255"},
		{"169.254.0.0", "169.254.255.255"},
	}
	parts := make([]string, 0, len(ranges))
	for _, addressRange := range ranges {
		parts = append(parts, fmt.Sprintf("(%s < %s or %s > %s)", field, addressRange[0], field, addressRange[1]))
	}
	return "(" + strings.Join(parts, " and ") + ")"
}

// captureFilter composes the final kernel filter for one direction.
func (c *windowsCaptureConfig) captureFilter(endpoint Endpoint, outbound bool) (*windivert.Filter, error) {
	if c == nil {
		return nil, fmt.Errorf("desync: capture.windows is not configured")
	}
	filter, err := c.envelope(endpoint, outbound)
	if err != nil {
		return nil, err
	}
	user, err := c.userExpression(endpoint, outbound)
	if err != nil {
		return nil, err
	}
	if user != "" {
		parsed, parseErr := windivert.ParseFilter(user)
		if parseErr != nil {
			return nil, parseErr
		}
		filter, err = windivert.And(filter, parsed)
		if err != nil {
			return nil, err
		}
	}
	if lan := c.lanExpression(endpoint, outbound); lan != "" {
		parsed, parseErr := windivert.ParseFilter(lan)
		if parseErr != nil {
			return nil, parseErr
		}
		filter, err = windivert.And(filter, parsed)
		if err != nil {
			return nil, err
		}
	}
	if count := filter.InstructionCount(); count < 0 {
		return nil, fmt.Errorf("desync: capture.windows filter does not compile")
	}
	return filter, nil
}

// writeFilterDump writes the composed filter text for both directions to the
// explicitly configured path. It is the upstream --wf-save bounded activation
// dump: opt-in only, 0600, truncated to the configured path, and it never
// happens during configuration compilation.
func (c *windowsCaptureConfig) writeFilterDump(endpoint Endpoint) error {
	if c == nil || c.filterSave == "" {
		return nil
	}
	var builder strings.Builder
	for _, outbound := range []bool{true, false} {
		if !outbound && !endpoint.Destination.IsValid() {
			continue
		}
		filter, err := c.captureFilter(endpoint, outbound)
		if err != nil {
			return err
		}
		direction := "inbound"
		if outbound {
			direction = "outbound"
		}
		builder.WriteString("# ")
		builder.WriteString(direction)
		builder.WriteString("\n")
		builder.WriteString(filter.Expression())
		builder.WriteString("\n")
	}
	content := builder.String()
	if len(content) > windivert.MaxFilterExpressionBytes() {
		return fmt.Errorf("desync: capture.windows.filter_save dump exceeds %d bytes", windivert.MaxFilterExpressionBytes())
	}
	return writeBoundedFile(c.filterSave, []byte(content))
}

func writeBoundedFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("desync: write %s: %w", path, err)
	}
	if _, err = file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("desync: write %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("desync: close %s: %w", path, err)
	}
	return nil
}
