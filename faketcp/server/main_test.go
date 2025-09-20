package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"net"
	"testing"
	"time"
)

// helper: reuse marshal/unmarshal declared in server.go if in same package.
// If not accessible, duplicate these small helpers here.
func mustResolveUDP(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return a
}

func readPacketWithTimeout(conn *net.UDPConn, timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	data := make([]byte, n)
	copy(data, buf[:n])
	return data, addr, nil
}

func TestServerHandshakeAndEcho(t *testing.T) {
	// avoid -test.v flag conflict when running manually
	flag.Parse()

	// start server on an ephemeral port
	srv, err := NewServer(":4000")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	// run server in background
	go srv.run()
	// ensure server is listening and get its actual address
	time.Sleep(50 * time.Millisecond)

	// create a client UDP socket
	clientConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("client ListenUDP failed: %v", err)
	}
	defer clientConn.Close()

	// resolve server address
	raddr := mustResolveUDP("127.0.0.1:4000")

	// build SYN
	clientSynSeq := uint32(12345)
	clientConnID := uint16(0x2000) // arbitrary client conn id in header
	synHdr := hdr{
		Ver:   1,
		Flags: FlagSYN,
		Conn:  clientConnID,
		Win:   1024,
		Seq:   clientSynSeq,
		Ack:   0,
	}
	//

	clientNonce := make([]byte, 12)
	rand.Read(clientNonce)

	// HMAC = HMAC-SHA256(PSK || nonce)
	h := hmac.New(sha256.New, []byte("supersecretkey123"))
	h.Write(clientNonce)
	clientHMAC := h.Sum(nil)

	synPayload := append(clientNonce, clientHMAC...)

	// header + payload
	synPacket := append(marshalHeader(synHdr), synPayload...)
	//
	_, err = clientConn.WriteToUDP(synPacket, raddr)
	if err != nil {
		t.Fatalf("send SYN failed: %v", err)
	}

	// read SYN|ACK
	data, addr, err := readPacketWithTimeout(clientConn, 2*time.Second)
	if err != nil {
		t.Fatalf("timeout or error waiting SYN/ACK: %v", err)
	}
	if addr.String() != raddr.String() {
		t.Fatalf("packet from unexpected addr: %s (want %s)", addr.String(), raddr.String())
	}
	respHdr, err := unmarshalHeader(data)
	if err != nil {
		t.Fatalf("unmarshalHeader failed: %v", err)
	}
	if respHdr.Flags&(FlagSYN|FlagACK) != (FlagSYN | FlagACK) {
		t.Fatalf("expected SYN|ACK, got flags=0x%02x", respHdr.Flags)
	}
	serverConnID := respHdr.Conn
	serverSeq := respHdr.Seq

	// send final ACK (ack serverSeq)
	finalAck := hdr{
		Ver:   1,
		Flags: FlagACK,
		Conn:  serverConnID,
		Win:   1024,
		Seq:   clientSynSeq + 1,
		Ack:   serverSeq,
	}
	_, err = clientConn.WriteToUDP(marshalHeader(finalAck), raddr)
	if err != nil {
		t.Fatalf("send final ACK failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	seq := clientSynSeq + 1
	for i := 0; i < 3; i++ {
		// send PSH payload with seq = clientSynSeq+1
		payload := []byte("hello faketcp from test")
		pshHdr := hdr{
			Ver:   1,
			Flags: FlagPSH,
			Conn:  serverConnID,
			Win:   1024,
			Seq:   seq,
			Ack:   0,
		}
		out := append(marshalHeader(pshHdr), payload...)
		_, err = clientConn.WriteToUDP(out, raddr)
		if err != nil {
			t.Fatalf("send PSH failed: %v", err)
		}

		// Expect: server first sends ACK (ack == seq)
		ackData, ackAddr, err := readPacketWithTimeout(clientConn, 2*time.Second)
		if err != nil {
			t.Fatalf("timeout waiting for ACK: %v", err)
		}
		if ackAddr.String() != raddr.String() {
			t.Fatalf("ack from unexpected addr: %s", ackAddr.String())
		}

		ackHdr, err := unmarshalHeader(ackData)
		if err != nil {
			t.Fatalf("unmarshal ack failed: %v", err)
		}
		if ackHdr.Flags&FlagACK == 0 {
			t.Fatalf("expected ACK flag, got 0x%02x", ackHdr.Flags)
		}
		if ackHdr.Ack != pshHdr.Seq {
			t.Fatalf("ack ack mismatch: got %d want %d", ackHdr.Ack, pshHdr.Seq)
		}
		// Then expect echo PSH from server (payload echoed)
		echoData, echoAddr, err := readPacketWithTimeout(clientConn, 2*time.Second)
		if err != nil {
			t.Fatalf("timeout waiting for echo: %v", err)
		}
		if echoAddr.String() != raddr.String() {
			t.Fatalf("echo from unexpected addr: %s", echoAddr.String())
		}
		echoHdr, err := unmarshalHeader(echoData)
		if err != nil {
			t.Fatalf("unmarshal echo failed: %v", err)
		}
		if echoHdr.Flags&FlagPSH == 0 {
			t.Fatalf("expected PSH flag in echo, got 0x%02x", echoHdr.Flags)
		}
		echoPayload := echoData[14:]
		if !bytes.Equal(echoPayload, payload) {
			t.Fatalf("echo payload mismatch: got %q want %q", string(echoPayload), string(payload))
		}
		seq++
	}
	// cleanup server socket
	_ = srv.pc.Close()
}

func TestServerHandshakeWithBadCode(t *testing.T) {
	// avoid -test.v flag conflict when running manually
	flag.Parse()

	// start server on an ephemeral port
	srv, err := NewServer(":4000")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	// run server in background
	go srv.run()
	// ensure server is listening and get its actual address
	time.Sleep(50 * time.Millisecond)

	// create a client UDP socket
	clientConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("client ListenUDP failed: %v", err)
	}
	defer clientConn.Close()

	// resolve server address
	raddr := mustResolveUDP("127.0.0.1:4000")

	// build SYN
	clientSynSeq := uint32(12345)
	clientConnID := uint16(0x2000) // arbitrary client conn id in header
	synHdr := hdr{
		Ver:   1,
		Flags: FlagSYN,
		Conn:  clientConnID,
		Win:   1024,
		Seq:   clientSynSeq,
		Ack:   0,
	}
	//

	clientNonce := make([]byte, 12)
	rand.Read(clientNonce)

	// HMAC = HMAC-SHA256(PSK || nonce)
	h := hmac.New(sha256.New, []byte("supersecretkey125"))
	h.Write(clientNonce)
	clientHMAC := h.Sum(nil)

	// payload که به SYN اضافه می‌کنیم: [nonce|HMAC]
	synPayload := append(clientNonce, clientHMAC...)

	// header + payload
	synPacket := append(marshalHeader(synHdr), synPayload...)
	//
	_, err = clientConn.WriteToUDP(synPacket, raddr)
	if err != nil {
		t.Fatalf("send SYN failed: %v", err)
	}

	// read SYN|ACK
	data, addr, err := readPacketWithTimeout(clientConn, 2*time.Second)
	if err != nil {
		t.Fatalf("timeout or error waiting SYN/ACK: %v", err)
	}
	if addr.String() != raddr.String() {
		t.Fatalf("packet from unexpected addr: %s (want %s)", addr.String(), raddr.String())
	}
	respHdr, err := unmarshalHeader(data)
	if err != nil {
		t.Fatalf("unmarshalHeader failed: %v", err)
	}
	// if respHdr.Conn == 0 {
	if respHdr.Conn != 0 {
		// expected server to reject with FIN|ACK and remove conn
		if respHdr.Flags&(FlagFIN|FlagACK) != (FlagFIN | FlagACK) {
			t.Fatalf("expected FIN|ACK, got flags=0x%02x", respHdr.Flags)
		}
	}
	// cleanup server socket
	_ = srv.pc.Close()
}
