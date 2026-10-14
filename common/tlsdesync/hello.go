package tlsdesync

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// cloneHello preserves the real session ID, cipher suites, key shares and
// extension order. Only the SNI and random are changed; nested lengths follow.
func cloneHello(b []byte, name string) ([]byte, error) {
	if len(b) < 44 || b[0] != 22 || b[5] != 1 || int(binary.BigEndian.Uint16(b[3:5]))+5 != len(b) || int(b[6])<<16|int(b[7])<<8|int(b[8]) != len(b)-9 {
		return nil, fmt.Errorf("tls_desync: expected one complete ClientHello record")
	}
	p := 43
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil, fmt.Errorf("tls_desync: truncated session ID")
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	if p >= len(b) {
		return nil, fmt.Errorf("tls_desync: truncated cipher suites")
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil, fmt.Errorf("tls_desync: truncated compression methods")
	}
	extLenAt := p
	p += 2
	if p+int(binary.BigEndian.Uint16(b[extLenAt:extLenAt+2])) != len(b) {
		return nil, fmt.Errorf("tls_desync: invalid extension length")
	}
	for p+4 <= len(b) {
		typ, n := binary.BigEndian.Uint16(b[p:p+2]), int(binary.BigEndian.Uint16(b[p+2:p+4]))
		if p+4+n > len(b) {
			break
		}
		if typ == 0 {
			if n < 5 || b[p+6] != 0 || int(binary.BigEndian.Uint16(b[p+4:p+6])) != n-2 || int(binary.BigEndian.Uint16(b[p+7:p+9])) != n-5 {
				return nil, fmt.Errorf("tls_desync: unsupported SNI list")
			}
			out := append([]byte(nil), b[:p+9]...)
			out = append(out, name...)
			out = append(out, b[p+4+n:]...)
			delta := len(out) - len(b)
			binary.BigEndian.PutUint16(out[3:5], uint16(len(out)-5))
			h := len(out) - 9
			out[6], out[7], out[8] = byte(h>>16), byte(h>>8), byte(h)
			binary.BigEndian.PutUint16(out[extLenAt:extLenAt+2], uint16(int(binary.BigEndian.Uint16(b[extLenAt:extLenAt+2]))+delta))
			binary.BigEndian.PutUint16(out[p+2:p+4], uint16(5+len(name)))
			binary.BigEndian.PutUint16(out[p+4:p+6], uint16(3+len(name)))
			binary.BigEndian.PutUint16(out[p+7:p+9], uint16(len(name)))
			if _, err := rand.Read(out[11:43]); err != nil {
				return nil, err
			}
			return out, nil
		}
		p += 4 + n
	}
	return nil, fmt.Errorf("tls_desync: SNI extension missing")
}
