//go:build !linux && !windows

package desync

import "fmt"

type unsupportedBackend struct{}

func NewNativeBackend() Backend { return unsupportedBackend{} }

func (unsupportedBackend) Name() string { return "unsupported" }

func (unsupportedBackend) Open(lease *Lease) (Capture, error) {
	return nil, fmt.Errorf("desync: native packet backends are implemented for linux and windows only")
}

func prepareSocket(lease *Lease, fd uintptr) error {
	return fmt.Errorf("desync: native packet backends are implemented for linux and windows only")
}
