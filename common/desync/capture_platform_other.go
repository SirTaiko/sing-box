//go:build !linux && !windows

package desync

import "fmt"

// platformError refuses both OS-specific capture blocks on a platform with no
// native capture backend. BSD divert/cookie is documented as non-target in the
// inventory, not silently accepted.
func (c captureConfig) platformError() error {
	if c.windows != nil {
		return fmt.Errorf("desync: capture.windows is only applicable on Windows")
	}
	if c.qnumSet || c.fwmarkSet || c.bindFix4 || c.bindFix6 {
		return fmt.Errorf("desync: capture.linux is only applicable on Linux")
	}
	return nil
}
