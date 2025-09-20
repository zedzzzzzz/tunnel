package pkg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

var ErrIncompleteFragment = errors.New("incomplete fragment")

// ------------------- ICMP Echo -------------------
func BuildICMPEcho(typ, code uint8, id, seq uint16, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	buf[0] = typ
	buf[1] = code
	// checksum 0 for now
	binary.BigEndian.PutUint16(buf[4:6], id)
	binary.BigEndian.PutUint16(buf[6:8], seq)
	copy(buf[8:], payload)
	check := icmpChecksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], check)
	return buf
}

func ParseICMPEcho(pkt []byte) (typ, code uint8, id, seq uint16, payload []byte, err error) {
	if len(pkt) < 8 {
		err = errors.New("packet too short")
		return
	}
	typ = pkt[0]
	code = pkt[1]
	id = binary.BigEndian.Uint16(pkt[4:6])
	seq = binary.BigEndian.Uint16(pkt[6:8])
	payload = pkt[8:]
	return
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ------------------- Fragment Payload -------------------
// Layout: session(2) + seq(2) + idx(1) + total(1) + data

func BuildFragmentPayload(session, seq uint16, idx, total uint8, data []byte) []byte {
	buf := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(buf[0:2], session)
	binary.BigEndian.PutUint16(buf[2:4], seq)
	buf[4] = idx
	buf[5] = total
	copy(buf[6:], data)
	return buf
}

func ParseFragmentPayload(buf []byte) (session, seq uint16, idx, total uint8, data []byte, err error) {
	if len(buf) < 6 {
		err = errors.New("fragment too short")
		return
	}
	session = binary.BigEndian.Uint16(buf[0:2])
	seq = binary.BigEndian.Uint16(buf[2:4])
	idx = buf[4]
	total = buf[5]
	data = buf[6:]
	return
}

// ------------------- Simple Fragment/Reassemble -------------------
type fragmentKey struct {
	session uint16
	seq     uint16
}

type reassembler struct {
	frags   map[fragmentKey]map[uint8][]byte
	expire  map[fragmentKey]time.Time
	timeout time.Duration
}

func NewReassembler(timeout time.Duration) *reassembler {
	return &reassembler{
		frags:   make(map[fragmentKey]map[uint8][]byte),
		expire:  make(map[fragmentKey]time.Time),
		timeout: timeout,
	}
}

func (r *reassembler) AddFragment(session, seq uint16, idx, total uint8, data []byte) (complete bool, assembled []byte, err error) {
	key := fragmentKey{session, seq}
	if _, ok := r.frags[key]; !ok {
		r.frags[key] = make(map[uint8][]byte)
		r.expire[key] = time.Now().Add(r.timeout)
	}
	r.frags[key][idx] = data

	// check if all fragments present
	if uint8(len(r.frags[key])) < total {
		err = ErrIncompleteFragment
		return
	}

	buf := bytes.Buffer{}
	for i := uint8(0); i < total; i++ {
		d, ok := r.frags[key][i]
		if !ok {
			err = ErrIncompleteFragment
			return
		}
		buf.Write(d)
	}
	assembled = buf.Bytes()
	complete = true
	delete(r.frags, key)
	delete(r.expire, key)
	return
}

// SimpleFragment splits data into chunks of size <= maxLen
func SimpleFragment(session, seq uint16, data []byte, maxLen int) ([][]byte, error) {
	if maxLen < 10 {
		return nil, errors.New("maxLen too small")
	}
	var frags [][]byte
	total := uint8((len(data) + maxLen - 1) / maxLen)
	if total == 0 {
		total = 1
	}
	for i := uint8(0); i < total; i++ {
		start := int(i) * maxLen
		end := start + maxLen
		if end > len(data) {
			end = len(data)
		}
		frags = append(frags, BuildFragmentPayload(session, seq, i, total, data[start:end]))
	}
	return frags, nil
}
