package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

var PSK = []byte("supersecretkey123")

const (
	nonceLen = 12
	hmacLen  = 32 // SHA256
)

const (
	FlagSYN = 1 << 0
	FlagACK = 1 << 1
	FlagFIN = 1 << 2
	FlagPSH = 1 << 3
)

type hdr struct {
	Ver   uint8
	Flags uint8
	Conn  uint16
	Win   uint16
	Seq   uint32
	Ack   uint32
}

func marshalHeader(h hdr) []byte {
	b := make([]byte, 14)
	b[0] = h.Ver
	b[1] = h.Flags
	binary.BigEndian.PutUint16(b[2:4], h.Conn)
	binary.BigEndian.PutUint16(b[4:6], h.Win)
	binary.BigEndian.PutUint32(b[6:10], h.Seq)
	binary.BigEndian.PutUint32(b[10:14], h.Ack)
	return b
}
func unmarshalHeader(b []byte) (hdr, error) {
	var h hdr
	if len(b) < 14 {
		return h, fmt.Errorf("short header")
	}
	h.Ver = b[0]
	h.Flags = b[1]
	h.Conn = binary.BigEndian.Uint16(b[2:4])
	h.Win = binary.BigEndian.Uint16(b[4:6])
	h.Seq = binary.BigEndian.Uint32(b[6:10])
	h.Ack = binary.BigEndian.Uint32(b[10:14])
	return h, nil
}

type ConnState struct {
	connID       uint16
	peer         *net.UDPAddr
	serverSeq    uint32
	expectedSeq  uint32
	lastActivity time.Time

	established bool
}

type Server struct {
	pc     *net.UDPConn
	mu     sync.Mutex
	conns  map[string]*ConnState
	nextID uint16
}

func NewServer(listen string) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		pc:     pc,
		conns:  make(map[string]*ConnState),
		nextID: 0x1000,
	}, nil
}

func (s *Server) run() {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handlePacket(raddr, data)
	}
}

func (s *Server) handlePacket(raddr *net.UDPAddr, pkt []byte) {
	h, err := unmarshalHeader(pkt)
	if err != nil {
		return
	}
	payload := pkt[14:]
	key := raddr.String()
	s.mu.Lock()
	cs, ok := s.conns[key]
	s.mu.Unlock()

	// New connection: expect SYN
	if !ok {
		func() {
			if h.Flags&FlagSYN == 0 {
				// ignore non-syn from unknown peer
				return
			}
			if len(payload) < nonceLen+hmacLen {
				log.Printf("invalid client HMAC from %s", key)
				s.mu.Lock()
				_, ok := s.conns[key]
				if ok {
					finHdr := hdr{
						Ver:   1,
						Flags: FlagFIN | FlagACK,
						Conn:  0,
						Win:   0,
						Seq:   0,
						Ack:   0,
					}
					_, _ = s.pc.WriteToUDP(marshalHeader(finHdr), raddr)
					delete(s.conns, key)
				}
				s.mu.Unlock()
				return
			}

			clientNonce := payload[:nonceLen]
			clientH := payload[nonceLen : nonceLen+hmacLen]
			expected := hmac.New(sha256.New, PSK)
			expected.Write(clientNonce)
			if !hmac.Equal(clientH, expected.Sum(nil)) {
				log.Printf("invalid client HMAC from %s", key)
				s.mu.Lock()
				_, ok := s.conns[key]
				if !ok {
					finHdr := hdr{
						Ver:   1,
						Flags: FlagFIN | FlagACK,
						Conn:  0,
						Win:   0,
						Seq:   0,
						Ack:   0,
					}
					_, _ = s.pc.WriteToUDP(marshalHeader(finHdr), raddr)
					delete(s.conns, key)
				}
				s.mu.Unlock()
				return
			}

			// allocate new conn state
			s.mu.Lock()
			id := s.nextID
			s.nextID++
			cs = &ConnState{
				connID:       id,
				peer:         raddr,
				serverSeq:    1000,
				expectedSeq:  h.Seq + 1,
				lastActivity: time.Now(),
				established:  true,
			}
			s.conns[key] = cs
			s.mu.Unlock()

			// send SYN|ACK
			respHdr := hdr{
				Ver:   1,
				Flags: FlagSYN | FlagACK,
				Conn:  id,
				Win:   1024,
				Seq:   cs.serverSeq,
				Ack:   h.Seq,
			}
			_, _ = s.pc.WriteToUDP(marshalHeader(respHdr), raddr)
		}()
		return
	}

	// existing conn
	cs.lastActivity = time.Now()

	// If this is ACK completing handshake (client acking server seq)
	if h.Flags&FlagACK != 0 && h.Ack == cs.serverSeq && !cs.established {
		// handshake done - keep expectedSeq as set earlier
		log.Printf("handshake done with %s connid=%d\n", key, cs.connID)
		return
	}

	// PSH (data)
	if h.Flags&FlagPSH != 0 {
		func() {
			// check seq
			if h.Seq != cs.expectedSeq {
				// send cumulative ACK for last delivered (expectedSeq-1)
				ackHdr := hdr{
					Ver:   1,
					Flags: FlagACK,
					Conn:  cs.connID,
					Win:   1024,
					Seq:   cs.serverSeq,
					Ack:   cs.expectedSeq - 1,
				}
				_, _ = s.pc.WriteToUDP(marshalHeader(ackHdr), cs.peer)
				return
			}
			// deliver payload (here: print)
			log.Printf("from %s payload(len=%d): %s", key, len(payload), string(payload))
			cs.expectedSeq++ // treat seq as message counter

			// send ACK
			ackHdr := hdr{
				Ver:   1,
				Flags: FlagACK,
				Conn:  cs.connID,
				Win:   1024,
				Seq:   cs.serverSeq,
				Ack:   h.Seq,
			}
			_, _ = s.pc.WriteToUDP(marshalHeader(ackHdr), cs.peer)

			// echo back as PSH
			cs.serverSeq++ // server uses its own seq counter
			pushHdr := hdr{
				Ver:   1,
				Flags: FlagPSH,
				Conn:  cs.connID,
				Win:   1024,
				Seq:   cs.serverSeq,
				Ack:   h.Seq,
			}
			out := append(marshalHeader(pushHdr), payload...)
			_, _ = s.pc.WriteToUDP(out, cs.peer)
		}()
		return
	}

	// FIN
	if h.Flags&FlagFIN != 0 {
		ackHdr := hdr{
			Ver:   1,
			Flags: FlagACK,
			Conn:  cs.connID,
			Win:   1024,
			Seq:   cs.serverSeq,
			Ack:   h.Seq,
		}
		_, _ = s.pc.WriteToUDP(marshalHeader(ackHdr), cs.peer)
		// cleanup
		s.mu.Lock()
		delete(s.conns, key)
		s.mu.Unlock()
		return
	}
}

func main() {
	listen := flag.String("l", ":4000", "listen UDP address")
	flag.Parse()

	srv, err := NewServer(*listen)
	if err != nil {
		log.Fatalf("NewServer: %v", err)
	}
	log.Printf("fake-tcp server listening %s", *listen)
	srv.run()
}
