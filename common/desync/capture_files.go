package desync

// Bounded file helpers and GUID validation shared by the Windows capture
// configuration. They are platform neutral so the configuration path is
// exercised by hermetic tests on the build host.

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// readBoundedFile reads at most limit bytes. A larger file is rejected rather
// than truncated: a silently truncated filter expression would be a different
// filter than the operator wrote.
func readBoundedFile(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("desync: read %s: %w", path, err)
	}
	defer file.Close()
	// Reject a regular file that is already known to be oversized before any
	// allocation; the stream limit below covers the remaining cases (a file
	// that grows between the check and the read, or a non-regular source).
	if info, statErr := file.Stat(); statErr == nil && info.Mode().IsRegular() && info.Size() > int64(limit) {
		return nil, fmt.Errorf("desync: read %s: file exceeds %d bytes", path, limit)
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("desync: read %s: %w", path, err)
	}
	if len(content) > limit {
		return nil, fmt.Errorf("desync: read %s: file exceeds %d bytes", path, limit)
	}
	return content, nil
}

// parseGUID validates the canonical 36-byte registry form
// XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX used by Network List Manager network
// ids and adapter ids.
func parseGUID(text string) ([16]byte, error) {
	var guid [16]byte
	if len(text) != 36 {
		return guid, fmt.Errorf("GUID %q is not 36 characters", text)
	}
	if text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return guid, fmt.Errorf("GUID %q has misplaced separators", text)
	}
	compact := strings.ReplaceAll(text, "-", "")
	if len(compact) != 32 {
		return guid, fmt.Errorf("GUID %q has an invalid layout", text)
	}
	for index := 0; index < 32; index++ {
		value, ok := guidHexDigit(compact[index])
		if !ok {
			return guid, fmt.Errorf("GUID %q contains a non-hex character", text)
		}
		if index%2 == 0 {
			guid[index/2] = value << 4
		} else {
			guid[index/2] |= value
		}
	}
	return guid, nil
}

func guidHexDigit(character byte) (byte, bool) {
	switch {
	case character >= '0' && character <= '9':
		return character - '0', true
	case character >= 'a' && character <= 'f':
		return character - 'a' + 10, true
	case character >= 'A' && character <= 'F':
		return character - 'A' + 10, true
	}
	return 0, false
}
