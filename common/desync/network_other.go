//go:build !windows

package desync

// defaultNetworkProbe returns no probe off Windows: capture.windows is not
// applicable there (see capture_platform_*.go), and the activation gate treats
// an absent platform implementation as inactive while every packet passes.
func defaultNetworkProbe() NetworkProbe { return nil }
