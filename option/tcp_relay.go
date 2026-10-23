package option

import (
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// TCPRelayPolicy is the validated relay policy of one listening TCP inbound.
// It is transport-only: the connection-pair owner applies it, no second proxy
// or state owner is created.
type TCPRelayPolicy struct {
	// DisableSplice selects an ordinary read/write copy in both directions,
	// without a syscall splice, ReaderFrom or WriterTo fast path.
	DisableSplice bool
	// MaxOrphanTime bounds a pending remote attempt after the local leg
	// terminally closed with unsent data. It is only meaningful together
	// with HasMaxOrphanTime.
	MaxOrphanTime time.Duration
	// HasMaxOrphanTime reports that tcp_max_orphan_time was configured.
	// An explicit zero disables only the orphan timer; the configured
	// connect deadline, caller cancellation and shutdown still apply.
	HasMaxOrphanTime bool
}

// Empty reports that no relay policy was configured. The connection-pair
// owner keeps the previous fast path in that case.
func (p TCPRelayPolicy) Empty() bool {
	return !p.DisableSplice && !p.HasMaxOrphanTime
}

// TCPRelayPolicy validates and returns the relay policy of these listen
// options. The relay fields are TCP-only; a UDP-listening inbound keeps them
// unused, like the other TCP listen fields.
func (o ListenOptions) TCPRelayPolicy() (TCPRelayPolicy, error) {
	policy := TCPRelayPolicy{
		DisableSplice: o.TCPDisableSplice,
	}
	if o.TCPMaxOrphanTime != nil {
		orphanTime := time.Duration(*o.TCPMaxOrphanTime)
		if orphanTime < 0 {
			return TCPRelayPolicy{}, E.New("tcp_max_orphan_time must not be negative")
		}
		policy.MaxOrphanTime = orphanTime
		policy.HasMaxOrphanTime = true
	}
	return policy, nil
}
