package direct

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/tlsdesync"
)

// TestLegacySameFlowConflictsAreActionable covers packet, stream and combined
// attachments: any enabled attachment reserves the same connection flow.
func TestLegacySameFlowConflictsAreActionable(t *testing.T) {
	streamOnly := &desync.StreamConfig{}
	for _, outbound := range []*Outbound{
		{desync: &desync.Engine{}},
		{stream: streamOnly},
		{desync: &desync.Engine{}, stream: streamOnly},
	} {
		cases := []struct {
			name     string
			mutate   func(metadata *adapter.InboundContext)
			expected string
		}{
			{"tls_desync", func(metadata *adapter.InboundContext) {
				metadata.TLSDesync = &tlsdesync.Options{}
			}, "tls_desync"},
			{"tls_fragment", func(metadata *adapter.InboundContext) {
				metadata.TLSFragment = true
			}, "tls_fragment"},
			{"tls_record_fragment", func(metadata *adapter.InboundContext) {
				metadata.TLSRecordFragment = true
			}, "tls_fragment"},
			{"tls_spoof", func(metadata *adapter.InboundContext) {
				metadata.TLSSpoof = "1.2.3.4"
			}, "tls_spoof"},
		}
		for _, testCase := range cases {
			ctx, metadata := adapter.ExtendContext(context.Background())
			testCase.mutate(metadata)
			err := outbound.checkLegacyConflict(ctx)
			if err == nil {
				t.Fatalf("%s: expected a conflict error", testCase.name)
			}
			if !contains(err.Error(), testCase.expected) {
				t.Fatalf("%s: error %q is not actionable", testCase.name, err)
			}
		}
	}
	// Disabled/absent desync must never reject the legacy options.
	plain := &Outbound{}
	ctx, metadata := adapter.ExtendContext(context.Background())
	metadata.TLSFragment = true
	if err := plain.checkLegacyConflict(ctx); err != nil {
		t.Fatalf("disabled desync must not conflict: %v", err)
	}
}

func contains(value, substring string) bool {
	return len(value) >= len(substring) && (value == substring || indexOf(value, substring) >= 0)
}

func indexOf(value, substring string) int {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return index
		}
	}
	return -1
}
