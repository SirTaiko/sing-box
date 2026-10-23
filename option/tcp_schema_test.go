package option

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
)

func TestTCPSocketOptionsSchema(t *testing.T) {
	content, err := schema.Generate(context.Background(), reflect.TypeFor[TCPSocketOptions]())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"receive_buffer_size"`, `"send_buffer_size"`, `"user_timeout"`} {
		if !bytes.Contains(content, []byte(field)) {
			t.Fatalf("schema misses %s: %s", field, content)
		}
	}
	if bytes.Contains(content, []byte(`"additionalProperties": true`)) {
		t.Fatalf("socket options must stay strict: %s", content)
	}
}

func TestTCPListenBindingSchema(t *testing.T) {
	content, err := schema.Generate(context.Background(), reflect.TypeFor[TCPListenBinding]())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"address"`, `"interface"`, `"ip_version"`, `"link_local"`,
		`"wait_ifup"`, `"wait_ip"`, `"wait_ip_linklocal"`,
		`"unwanted"`, `"no"`, `"prefer"`, `"force"`,
	} {
		if !bytes.Contains(content, []byte(field)) {
			t.Fatalf("schema misses %s: %s", field, content)
		}
	}
}
