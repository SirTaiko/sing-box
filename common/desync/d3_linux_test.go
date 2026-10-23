//go:build linux

package desync

import (
	"testing"

	"github.com/sagernet/nftables/expr"
)

// TestInterfaceNameCompare pins the owned-device selector construction: the
// rule matches the actual native-attempt interface name only, with the
// nftables 4-byte string padding.
func TestInterfaceNameCompare(t *testing.T) {
	exprs := interfaceNameCompare(expr.MetaKeyOIFNAME, "eth0")
	if len(exprs) != 2 {
		t.Fatalf("expression count = %d", len(exprs))
	}
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyOIFNAME || meta.Register != 1 {
		t.Fatalf("meta expression = %#v", exprs[0])
	}
	cmp, ok := exprs[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 {
		t.Fatalf("cmp expression = %#v", exprs[1])
	}
	if string(cmp.Data) != "eth0" {
		t.Fatalf("interface data = %q", string(cmp.Data))
	}
	if len(cmp.Data)%4 != 0 {
		t.Fatalf("interface data is not 4-byte padded: %d", len(cmp.Data))
	}
	// The input direction uses iifname for the same owned device.
	inbound := interfaceNameCompare(expr.MetaKeyIIFNAME, "wg-test")
	meta, ok = inbound[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("inbound meta = %#v", inbound[0])
	}
	// Callers only invoke the builder for a non-empty owned device name
	// (installRules gates on endpoint.Interface), so an unbound attempt never
	// gains an interface predicate.
}
