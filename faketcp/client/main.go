package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
)

var PSK = []byte("supersecretkey123")

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

func handshake(conn *net.UDPConn, raddr *net.UDPAddr, connID uint16) error {
	// send SYN
	//

	clientNonce := make([]byte, 12)
	rand.Read(clientNonce)
	clientH := hmac.New(sha256.New, PSK)
	clientH.Write(clientNonce)
	synPayload := append(clientNonce, clientH.Sum(nil)...)
	//
	seq := uint32(rand.Int31())
	syn := hdr{Ver: 1, Flags: FlagSYN, Conn: connID, Win: 1024, Seq: seq, Ack: 0}
	bytes := append(marshalHeader(syn), synPayload...)

	// _, err := conn.WriteToUDP(marshalHeader(syn), raddr)
	_, err := conn.WriteToUDP(bytes, raddr)
	if err != nil {
		return err
	}

	// wait SYN|ACK
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if addr.String() != raddr.String() {
			continue
		}
		h, err := unmarshalHeader(buf[:n])
		if err != nil {
			continue
		}
		if h.Flags&(FlagSYN|FlagACK) == (FlagSYN | FlagACK) {
			// send final ACK
			ack := hdr{Ver: 1, Flags: FlagACK, Conn: connID, Win: 1024, Seq: seq + 1, Ack: h.Seq}
			_, err = conn.WriteToUDP(marshalHeader(ack), raddr)
			return err
		}
	}
}

func sendReliable(conn *net.UDPConn, raddr *net.UDPAddr, connID uint16, seq uint32, payload []byte) error {
	for tries := 0; tries < 5; tries++ {
		pkt := append(marshalHeader(hdr{Ver: 1, Flags: FlagPSH, Conn: connID, Win: 1024, Seq: seq, Ack: 0}), payload...)
		_, err := conn.WriteToUDP(pkt, raddr)
		if err != nil {
			return err
		}
		// wait for ACK
		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(1<<tries)))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// timeout -> retransmit
			continue
		}
		if addr.String() != raddr.String() {
			continue
		}
		h, err := unmarshalHeader(buf[:n])
		if err != nil {
			continue
		}
		if h.Flags&FlagACK != 0 && h.Ack == seq {
			return nil
		}
	}
	return fmt.Errorf("no ack")
}

func main() {
	server := flag.String("server", "127.0.0.1:4000", "server UDP address")
	msg := flag.String("msg", "hello faketcp", "message to send")
	flag.Parse()

	raddr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	connID := uint16(0x2000)
	if err := handshake(conn, raddr, connID); err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	log.Println("handshake done")

	seq := uint32(1)
	if err := sendReliable(conn, raddr, connID, seq, []byte(*msg)); err != nil {
		log.Fatalf("send failed: %v", err)
	}
	log.Println("sent payload, waiting for echo...")

	// wait for echo (PSH)
	buf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("read echo err: %v", err)
	}
	if addr.String() != raddr.String() {
		log.Fatalf("echo from unexpected peer %s", addr.String())
	}
	h, err := unmarshalHeader(buf[:n])
	if err != nil {
		log.Fatalf("bad hdr: %v", err)
	}
	if h.Flags&FlagPSH != 0 {
		payload := buf[14:n]
		log.Printf("echo payload: %s", string(payload))
	} else {
		log.Printf("got non-psh hdr flags=%02x", h.Flags)
	}
}
