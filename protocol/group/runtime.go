package group

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing/service"
)

// Stable interruption groups let a subsequent server switch also reach flows
// accepted before a DNS/protocol edit. Group tags are unique within one core.
type RuntimeInterrupts struct {
	groups sync.Map
}

func interruptGroupFor(ctx context.Context, tag string) *interrupt.Group {
	if store := service.PtrFromContext[RuntimeInterrupts](ctx); store != nil {
		group, _ := store.groups.LoadOrStore(tag, interrupt.NewGroup())
		return group.(*interrupt.Group)
	}
	return interrupt.NewGroup()
}
