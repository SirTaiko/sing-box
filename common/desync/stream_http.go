package desync

import (
	"bytes"
	"io"
)

// HTTP parsing below is a byte-faithful port of pinned tpws protocol.c:
// HttpMethod, FindHostIn/IsHostAt and the tamper_out HTTP branch of tamper.c
// (zapret v72.9 c849e55e). Only the first block is inspected, exactly like a
// tpws receive block. The upstream MIT copyright and permission notice for
// this derived code is reproduced in UPSTREAM_LICENSE_zapret_tpws.txt.

var streamHTTPMethods = []string{
	"GET /", "POST /", "HEAD /", "OPTIONS ", "PUT /", "DELETE /", "CONNECT ", "TRACE /",
}

// httpMethod returns the matched upstream method spelling. tpws derives the
// method split anchor as len(method)-2, so the spelling including its trailing
// space/slash is significant.
func streamHTTPMethod(block []byte) (string, bool) {
	for _, method := range streamHTTPMethods {
		if len(block) >= len(method) && bytes.Equal(block[:len(method)], []byte(method)) {
			return method, true
		}
	}
	return "", false
}

// isHostAt mirrors tpws IsHostAt: a case-insensitive `Host:` preceded by LF.
func isHostAt(data []byte, offset int) bool {
	if offset+6 > len(data) {
		return false
	}
	return data[offset] == '\n' &&
		(data[offset+1] == 'H' || data[offset+1] == 'h') &&
		(data[offset+2] == 'o' || data[offset+2] == 'O') &&
		(data[offset+3] == 's' || data[offset+3] == 'S') &&
		(data[offset+4] == 't' || data[offset+4] == 'T') &&
		data[offset+5] == ':'
}

// findHostHeader returns the offset of the `H` of the first Host header, or
// -1. This is the tpws HttpFindHost result.
func findHostHeader(data []byte) int {
	if len(data) < 6 {
		return -1
	}
	for offset := 0; offset <= len(data)-6; offset++ {
		if isHostAt(data, offset) {
			return offset + 1
		}
	}
	return -1
}

// hostValueBounds returns the host value after `Host:`. As in tpws HttpPos, at
// most one leading space or tab is skipped; the value ends at CR or LF, and
// terminated reports whether that terminator was actually present in the
// block. An unterminated value must not be used for deferred rule selection:
// more bytes can still extend the host.
func hostValueBounds(data []byte, hostOffset int) (start int, end int, ok bool, terminated bool) {
	if hostOffset < 0 || hostOffset+7 >= len(data) {
		return 0, 0, false, false
	}
	start = hostOffset + 5
	if start < len(data) && (data[start] == ' ' || data[start] == '	') {
		start++
	}
	end = start
	for end < len(data) && data[end] != '\r' && data[end] != '\n' {
		end++
	}
	return start, end, true, end < len(data)
}

// findNLD is a port of tpws protocol.c FindNLD: locate the `level`-th level
// domain inside dom. level 2 is the second-level domain.
func findNLD(dom []byte, level int) (start int, end int, ok bool) {
	if level < 1 || len(dom) == 0 {
		return 0, 0, false
	}
	p2 := len(dom)
	for i := 1; i < level; i++ {
		for {
			p2--
			if p2 <= 0 || dom[p2] == '.' {
				break
			}
		}
		if p2 <= 0 {
			return 0, 0, false
		}
	}
	p1 := p2 - 1
	for p1 > 0 && dom[p1] != '.' {
		p1--
	}
	if dom[p1] == '.' {
		p1++
	}
	return p1, p2, true
}

func insertBytes(block []byte, at int, insert []byte) ([]byte, bool) {
	if at < 0 || at > len(block) || len(block)+len(insert) > cap(block) {
		return block, false
	}
	oldLength := len(block)
	block = block[:oldLength+len(insert)]
	copy(block[at+len(insert):], block[at:oldLength])
	copy(block[at:], insert)
	return block, true
}

func removeByte(block []byte, at int) []byte {
	copy(block[at:], block[at+1:])
	return block[:len(block)-1]
}

// unixEOL mirrors the tamper.c loop: replace CRLF with LF until (and
// including) the first double EOL, then stop. Bytes after the header block are
// left untouched.
func unixEOL(block []byte) []byte {
	search := 0
	previousLF := -2
	for {
		relative := bytes.Index(block[search:], []byte("\r\n"))
		if relative < 0 {
			return block
		}
		position := search + relative
		block[position] = '\n'
		copy(block[position+1:], block[position+2:])
		block = block[:len(block)-1]
		if previousLF == position-1 {
			return block
		}
		previousLF = position
		search = position + 1
	}
}

type streamRandom struct {
	source io.Reader
}

func (r *streamRandom) byte() (byte, error) {
	var buffer [1]byte
	if _, err := io.ReadFull(r.source, buffer[:]); err != nil {
		return 0, err
	}
	return buffer[0], nil
}

func (r *streamRandom) letter() (byte, error) {
	value, err := r.byte()
	if err != nil {
		return 0, err
	}
	return 'a' + value%('z'-'a'+1), nil
}

func (r *streamRandom) word() (uint16, error) {
	var buffer [2]byte
	if _, err := io.ReadFull(r.source, buffer[:]); err != nil {
		return 0, err
	}
	return uint16(buffer[0])<<8 | uint16(buffer[1]), nil
}

// applyHTTPTamper performs the tamper_out HTTP transformations in their exact
// upstream order. block must be a mutable slice whose capacity is the tpws
// segment buffer; the returned slice may be shorter or longer.
func applyHTTPTamper(block []byte, spec *httpTamperSpec, random *streamRandom) ([]byte, error) {
	methodLength := 0
	if method, ok := streamHTTPMethod(block); ok {
		methodLength = len(method) - 2
	}
	if spec.unixEOL {
		block = unixEOL(block)
	}
	if spec.methodEOL {
		lineEnd := []byte{'\r', '\n'}
		if spec.unixEOL {
			lineEnd = []byte{'\n'}
		}
		counted, ok := insertBytes(block, 0, lineEnd)
		if ok {
			block = counted
		}
	}
	if spec.methodSpace && len(block) < cap(block) {
		if counted, ok := insertBytes(block, methodLength+1, []byte{' '}); ok {
			block = counted
		}
	}
	if (spec.hostDot || spec.hostTab) && len(block) < cap(block) {
		if hostOffset := findHostHeader(block); hostOffset >= 0 {
			position := hostOffset + 5
			for position < len(block) && block[position] != '\r' && block[position] != '\n' {
				position++
			}
			if position < len(block) {
				character := byte('.')
				if !spec.hostDot {
					character = '\t'
				}
				if counted, ok := insertBytes(block, position, []byte{character}); ok {
					block = counted
				}
			}
		}
	}
	if spec.domCase {
		if hostOffset := findHostHeader(block); hostOffset >= 0 {
			for position := hostOffset + 5; position < len(block) &&
				block[position] != '\r' && block[position] != '\n'; position++ {
				if position&1 != 0 {
					block[position] = lowerASCII(block[position])
				} else {
					block[position] = upperASCII(block[position])
				}
			}
		}
	}
	if spec.hostNoSpace {
		if hostOffset := findHostHeader(block); hostOffset >= 0 &&
			hostOffset+5 < len(block) && block[hostOffset+5] == ' ' {
			block = removeByte(block, hostOffset+5)
		}
	}
	if spec.hostCase {
		if hostOffset := findHostHeader(block); hostOffset >= 0 && hostOffset+4 <= len(block) {
			copy(block[hostOffset:hostOffset+4], spec.hostSpell[:])
		}
	}
	if spec.hostPad != 0 {
		if hostOffset := findHostHeader(block); hostOffset >= 0 {
			headerSize := 9
			if spec.unixEOL {
				headerSize = 8
			}
			if headerSize+len(block) > cap(block) {
				return block, nil
			}
			padLength := spec.hostPad
			if padLength < headerSize {
				padLength = headerSize
			}
			if padLength+len(block) > cap(block) {
				padLength = cap(block) - len(block)
			}
			counted, ok := insertBytes(block, hostOffset, make([]byte, padLength))
			if !ok {
				return block, nil
			}
			// insertBytes copies a zero-filled region at hostOffset; fill the
			// dummy header lines exactly like tamper.c.
			position := hostOffset
			remaining := padLength
			for remaining > 0 {
				padSize := 0
				if remaining > headerSize {
					padSize = remaining - headerSize
				}
				const maxHeaderSize = 2048
				if padSize > maxHeaderSize {
					padSize = maxHeaderSize
				}
				if remaining-padSize-headerSize < headerSize {
					padSize += remaining - padSize - headerSize
				}
				letter, err := random.letter()
				if err != nil {
					return counted, err
				}
				value, err := random.word()
				if err != nil {
					return counted, err
				}
				header := []byte{letter, hexDigit(value >> 12), hexDigit(value >> 8), hexDigit(value >> 4), hexDigit(value), ':', ' '}
				copy(counted[position:position+7], header)
				position += 7
				for index := 0; index < padSize; index++ {
					fill, err := random.letter()
					if err != nil {
						return counted, err
					}
					counted[position] = fill
					position++
				}
				if spec.unixEOL {
					counted[position] = '\n'
					position++
				} else {
					counted[position] = '\r'
					counted[position+1] = '\n'
					position += 2
				}
				remaining -= headerSize + padSize
			}
			block = counted
		}
	}
	return block, nil
}

func lowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func upperASCII(value byte) byte {
	if value >= 'a' && value <= 'z' {
		return value - ('a' - 'A')
	}
	return value
}

func hexDigit(value uint16) byte {
	value &= 0xF
	if value < 10 {
		return '0' + byte(value)
	}
	return 'a' + byte(value-10)
}
