package zapret

import (
	"os"
	"slices"
	"strings"
)

// The upstream --comment option is inert, including in older releases. Only a
// recipe whose author declares that unrelated flows do not supply shared state
// may opt in. Arbitrary Lua cannot be analyzed from its port options alone.
const profilePortCapture = "--comment=mvpn-capture-profile-ports-v1"

type capturePortRange struct {
	first, last int
}

type capturePorts struct {
	tcp, udp []capturePortRange // nil retains the original capture for the protocol
}

func (p *profile) capturePorts() capturePorts {
	if p == nil || os.Getenv("MVPN_ZAPRET_DEBUG") == "1" {
		return capturePorts{}
	}
	return recipeCapturePorts(p.tokens)
}

func recipeCapturePorts(tokens []string) capturePorts {
	if len(tokens) == 0 || tokens[0] != profilePortCapture {
		return capturePorts{}
	}
	// Keep zero (unusable or ambiguous port) even if a transport is absent.
	result := capturePorts{tcp: []capturePortRange{{0, 0}}, udp: []capturePortRange{{0, 0}}}
	filtered := false
	for _, token := range tokens[1:] {
		name, value, _ := strings.Cut(token, "=")
		switch name {
		case "--new":
			if !filtered {
				return capturePorts{}
			}
			filtered = false
		case "--filter-tcp", "--filter-udp":
			filtered = true
			ports := &result.tcp
			if name == "--filter-udp" {
				ports = &result.udp
			}
			if *ports == nil {
				continue
			}
			if value == "*" || strings.Contains(value, "~") {
				*ports = nil
				continue
			}
			for part := range strings.SplitSeq(value, ",") {
				lo, hi, interval := strings.Cut(part, "-")
				first, err := parsePort(lo)
				if err != nil {
					return capturePorts{}
				}
				last := first
				if interval {
					last, err = parsePort(hi)
					if err != nil || last < first {
						return capturePorts{}
					}
				}
				*ports = append(*ports, capturePortRange{first, last})
			}
		case "--lua-init", "--lua-desync", "--blob", "--filter-l3", "--filter-l7",
			"--ipset", "--ipset-ip", "--ipset-exclude", "--ipset-exclude-ip",
			"--hostlist", "--hostlist-domains", "--hostlist-exclude", "--hostlist-exclude-domains",
			"--payload", "--payload-disable", "--in-range", "--out-range", "--comment", "--name":
			// These options cannot expand a branch's transport port filters.
		default:
			// Templates, imports, automatic lists and future options stay broad.
			return capturePorts{}
		}
	}
	if !filtered {
		return capturePorts{}
	}
	result.tcp = mergeCaptureRanges(result.tcp)
	result.udp = mergeCaptureRanges(result.udp)
	for _, span := range result.udp {
		// A wildcard UDP socket can receive first. A gaming range covering
		// every unprivileged local port makes testing both endpoints wasteful.
		if span.first <= 1024 && span.last == 65535 {
			result.udp = nil
			break
		}
	}
	return result
}

func mergeCaptureRanges(ports []capturePortRange) []capturePortRange {
	slices.SortFunc(ports, func(a, b capturePortRange) int { return a.first - b.first })
	merged := ports[:0]
	for _, span := range ports {
		n := len(merged)
		if n != 0 && span.first <= merged[n-1].last+1 {
			merged[n-1].last = max(merged[n-1].last, span.last)
		} else {
			merged = append(merged, span)
		}
	}
	// Bound driver instruction count as well as the textual filter length.
	if len(merged) > 8 || (len(merged) == 1 && merged[0] == (capturePortRange{0, 65535})) {
		return nil
	}
	return merged
}
