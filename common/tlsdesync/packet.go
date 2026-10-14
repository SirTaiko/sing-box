package tlsdesync

import (
	"encoding/binary"
	"fmt"
)

func packetPayload(frame []byte) (int, error) {
	if len(frame) < 40 || frame[0]>>4 != 4 || frame[9] != 6 || binary.BigEndian.Uint16(frame[6:8])&0x3fff != 0 {
		return 0, fmt.Errorf("tls_desync: expected unfragmented IPv4/TCP")
	}
	ip := int(frame[0]&15) * 4
	if ip < 20 || ip+20 > len(frame) {
		return 0, fmt.Errorf("tls_desync: truncated IP header")
	}
	start := ip + int(frame[ip+12]>>4)*4
	if start < ip+20 || start > len(frame) || int(binary.BigEndian.Uint16(frame[2:4])) != len(frame) {
		return 0, fmt.Errorf("tls_desync: truncated TCP header")
	}
	return start, nil
}

func makePacket(frame, payload []byte, sequence uint32, ttl int, md5, corrupt bool) []byte {
	ip := int(frame[0]&15) * 4
	start, _ := packetPayload(frame)
	out := append([]byte(nil), frame[:start]...)
	if md5 {
		// Strip existing options so the MD5 option fits in the 60-byte header.
		out = out[:ip+20]
		out[ip+12] = 10 << 4
		out = append(out, 19, 18)
		out = append(out, make([]byte, 18)...)
	}
	out = append(out, payload...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint32(out[ip+4:ip+8], sequence)
	if ttl > 0 {
		out[8] = byte(ttl)
	}
	out[10], out[11], out[ip+16], out[ip+17] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:ip], 0))
	sum := uint32(6 + len(out) - ip)
	for p := 12; p < 20; p += 2 {
		sum += uint32(binary.BigEndian.Uint16(out[p : p+2]))
	}
	c := checksum(out[ip:], sum)
	if corrupt {
		c ^= 0xffff
	}
	binary.BigEndian.PutUint16(out[ip+16:ip+18], c)
	return out
}

func checksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (o Options) packets(frame []byte) ([][]byte, error) {
	start, err := packetPayload(frame)
	if err != nil {
		return nil, err
	}
	hello := frame[start:]
	points, err := o.splitPoints(hello)
	if err != nil {
		return nil, err
	}
	var fake []byte
	if o.FakeSNI != "" {
		fake, err = cloneHello(hello, o.FakeSNI)
		if err != nil {
			return nil, err
		}
	}
	ip := int(frame[0]&15) * 4
	seq := binary.BigEndian.Uint32(frame[ip+4 : ip+8])
	var packets [][]byte
	for i := 0; i < o.FakeRepeats; i++ {
		fakeSeq := seq
		if o.FakeMethod == "" || o.FakeMethod == "wrong-sequence" {
			fakeSeq -= uint32(len(fake))
		}
		template := append([]byte(nil), frame...)
		if o.FakeMethod == "wrong-ack" {
			ack := binary.BigEndian.Uint32(template[ip+8 : ip+12])
			binary.BigEndian.PutUint32(template[ip+8:ip+12], ack-32767)
		}
		packets = append(packets, makePacket(template, fake, fakeSeq, o.FakeTTL, o.FakeMethod == "wrong-md5", o.FakeMethod == "wrong-checksum"))
	}
	var real [][]byte
	previous := 0
	for _, end := range points {
		payload := hello[previous:end]
		packetSeq := seq + uint32(previous)
		if previous == 0 && o.Overlap > 0 {
			pattern := fake
			if len(o.pattern) > 0 {
				pattern = o.pattern
			}
			prefix := make([]byte, o.Overlap)
			for i := range prefix {
				prefix[i] = pattern[i%len(pattern)]
			}
			payload = append(prefix, payload...)
			packetSeq -= uint32(o.Overlap)
		}
		real = append(real, makePacket(frame, payload, packetSeq, 0, false, false))
		previous = end
	}
	if o.Mode == "multidisorder" {
		for i := len(real) - 1; i >= 0; i-- {
			packets = append(packets, real[i])
		}
	} else {
		packets = append(packets, real...)
	}
	return packets, nil
}
