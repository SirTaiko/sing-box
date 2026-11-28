//go:build !windows && !linux

package zapret

func engineSupported() bool {
	return false
}

func newPlatformEngine(options platformOptions) (platformEngine, error) {
	return nil, ErrUnsupported
}
