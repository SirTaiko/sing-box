package desync

import (
	"errors"
	"fmt"
)

// packetInjection preserves the backend callback of one captured record. A
// batch is synchronous: its bytes are borrowed only until send returns. sent is
// the prefix confirmed by successful send returns, not a peer acknowledgement.
// Public Injector callers (including Windows) retain their per-record closure.
type batchInjector func(packets [][]byte) (sent int, err error)

type packetInjection struct {
	single Injector
	batch  batchInjector
}

func (i packetInjection) available() bool { return i.single != nil || i.batch != nil }

func (i packetInjection) send(packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if i.batch != nil {
		sent, err := i.batch(packets)
		if sent < 0 || sent > len(packets) {
			return 0, errors.Join(fmt.Errorf("desync: invalid injection progress %d of %d", sent, len(packets)), err)
		}
		if err == nil && sent != len(packets) {
			err = fmt.Errorf("desync: short injection progress %d of %d", sent, len(packets))
		}
		// Never resend a prefix or fall back to single after a batch callback,
		// including cleanup errors returned after every packet was sent.
		return sent, err
	}
	if i.single == nil {
		return 0, fmt.Errorf("desync: no packet injector")
	}
	for index, packet := range packets {
		if err := i.single(packet); err != nil {
			return index, err
		}
	}
	return len(packets), nil
}
