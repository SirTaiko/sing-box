//go:build linux

package desync

import "fmt"

// platformError refuses the OS-specific capture block of another platform. A
// capture.windows block on Linux would otherwise be accepted by the shared
// schema and silently do nothing, which is exactly the schema-only completion
// this increment must not produce.
func (c captureConfig) platformError() error {
	if c.windows != nil {
		return fmt.Errorf("desync: capture.windows is only applicable on Windows")
	}
	return nil
}
