//go:build windows

package desync

import "fmt"

// platformError refuses the OS-specific capture block of another platform on
// Windows: the Linux NFQUEUE identity/mark/bind-fix controls have no meaning
// for a WinDivert capture, so accepting them would be a silent no-op.
func (c captureConfig) platformError() error {
	if c.qnumSet {
		return fmt.Errorf("desync: capture.linux.qnum is only applicable on Linux")
	}
	if c.fwmarkSet {
		return fmt.Errorf("desync: capture.linux.fwmark is only applicable on Linux")
	}
	if c.bindFix4 || c.bindFix6 {
		return fmt.Errorf("desync: capture.linux.bind_fix4/6 is only applicable on Linux")
	}
	return nil
}
