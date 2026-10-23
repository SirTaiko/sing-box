package socks

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
)

func TestSocksInboundOptionsSchema(t *testing.T) {
	content, err := schema.Generate(context.Background(), reflect.TypeFor[option.SocksInboundOptions]())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"no_resolve"`, `"resolver_concurrency"`, `"domain_resolver"`} {
		if !bytes.Contains(content, []byte(field)) {
			t.Fatalf("schema misses %s: %s", field, content)
		}
	}
	if bytes.Contains(content, []byte(`"additionalProperties": true`)) {
		t.Fatalf("socks inbound options must stay strict: %s", content)
	}
}
