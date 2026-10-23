package desync

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RequiresZeroIPID reports whether any enabled rule requests zero IPv4 ID,
// which needs the owned native priority rewrite rule.
func (c *Config) RequiresZeroIPID() bool {
	for _, rule := range c.Rules {
		if rule.IPID == IPIDZero {
			return true
		}
	}
	return false
}

// MatchFacts are the facts available to rule matching at one selection point.
type MatchFacts struct {
	Family      Family
	Transport   Transport
	Destination netip.Addr
	Port        uint16
	Protocol    Protocol
	Host        string
	HostKnown   bool
	// Interface is the native attempt's actual interface fact: the device the
	// owned socket is bound to (SO_BINDTODEVICE / IP_UNICAST_IF), or the
	// dialer-supplied interface when the socket reports none. It scopes the
	// preconnect ip-cache lookup to the interface the attempt really uses, so
	// a host learned on another device is never substituted. Empty means the
	// attempt is not interface-bound and the outbound-scoped lookup applies.
	Interface string
	// HostIsIP marks a Host that is an IP literal (upstream hostname_is_ip):
	// hostlist matching is exact, subdomains do not exist.
	HostIsIP bool
	// Learned marks a host known to belong to this outbound's auto-hostlist
	// set (upstream auto hostlist entry). It is filled by the flow from the
	// engine-owned learner; it never comes from configuration.
	Learned bool
}

// Matches applies the rule's non-method predicates. Lists within a category
// are ORed, categories are ANDed and exclusions take precedence.
func (r *Rule) Matches(facts MatchFacts) bool {
	if r.Network&TransportMaskTCP != 0 && facts.Transport == TransportTCP {
	} else if r.Network&TransportMaskUDP != 0 && facts.Transport == TransportUDP {
	} else {
		return false
	}
	if facts.Family == FamilyIPv4 && !r.IPv4 {
		return false
	}
	if facts.Family == FamilyIPv6 && !r.IPv6 {
		return false
	}
	if len(r.Ports) > 0 {
		matched := false
		for _, portRange := range r.Ports {
			if portRange.Contains(facts.Port) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, portRange := range r.PortExclude {
		if portRange.Contains(facts.Port) {
			return false
		}
	}
	if !r.IPs.wildcard() && (r.IPs.restricts() || r.ipRestrict) {
		if !r.IPs.contains(facts.Destination) {
			return false
		}
	}
	if r.IPsExclude.wildcard() || r.IPsExclude.contains(facts.Destination) {
		return false
	}
	if (!r.Domains.empty() || r.domainRestrict) && r.Learning == nil {
		if !facts.HostKnown {
			return false
		}
		if !r.Domains.matchesHost(facts.Host, facts.HostIsIP) {
			return false
		}
	}
	if r.DomainsExclude.matches(facts.Host) {
		return false
	}
	if !r.AnyProtocol {
		if facts.Protocol == ProtocolUnknown && r.SkipNoSNI {
			return false
		}
		matched := false
		for _, protocol := range r.Protocols {
			if protocol == facts.Protocol {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
