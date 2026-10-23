package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// DirectDesyncListBundle selects immutable datasets of one
// `desync.list-bundle/v1` generation produced by
// `sing-box tools desync list-refresh`. The manifest is read exactly once per
// distinct canonical bundle root per compile/reload; the compiler never
// fetches, resolves or watches anything.
//
// The four arrays select dataset IDs (see the D5 contract dataset table).
// Every array defaults to empty and at least one dataset must be selected.
// Positive domain and IP categories keep their existing AND semantics; entries
// and files inside one category stay OR; exclusions always win. Inline and file
// list fields of the same rule remain additive with exactly their previous
// meaning.
type DirectDesyncListBundle struct {
	// Manifest is the required path of the bundle commit point
	// (DIRECTORY/current.json), resolved against the configuration base path
	// when relative.
	Manifest string `json:"manifest"`

	// Domain and DomainExclude select domain datasets (kind=domain).
	Domain        badoption.Listable[string] `json:"domain,omitempty"`
	DomainExclude badoption.Listable[string] `json:"domain_exclude,omitempty"`

	// IPCIDR and IPCIDRExclude select IP datasets (kind=ip, family 4/6).
	IPCIDR        badoption.Listable[string] `json:"ip_cidr,omitempty"`
	IPCIDRExclude badoption.Listable[string] `json:"ip_cidr_exclude,omitempty"`
}
