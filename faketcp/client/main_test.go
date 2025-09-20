package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// mock server behavior:
// - on SYN -> reply SYN|ACK (with some server seq)
// - on PSH -> reply ACK (ack = received seq) and then send PSH echo with same payload
func runMockServer(t *testing.T, listen string, stopCh <-chan struct{}) (string, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return "", err
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return "", err
	}

	go func() {
		defer sock.Close()
		buf := make([]byte, 65536)
		// simple state: we don't keep per-peer complex state, we just respond appropriately
		for {
			// non-blocking check stop
			select {
			case <-stopCh:
				return
			default:
			}
			_ = sock.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, raddr, err := sock.ReadFromUDP(buf)
			if err != nil {
				// timeout or other -> loop again
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				// other error: log and exit goroutine
				t.Logf("server read error: %v", err)
				return
			}
			if n < 14 {
				// too short ignore
				continue
			}
			h, err := unmarshalHeader(buf[:n])
			if err != nil {
				continue
			}

			// handle SYN
			if h.Flags&FlagSYN != 0 {
				// reply SYN|ACK
				resp := hdr{
					Ver:   1,
					Flags: FlagSYN | FlagACK,
					Conn:  0x1000,
					Win:   1024,
					Seq:   9999, // server seq
					Ack:   h.Seq,
				}
				_, _ = sock.WriteToUDP(marshalHeader(resp), raddr)
				continue
			}

			// handle PSH: send ACK then echo PSH
			if h.Flags&FlagPSH != 0 {
				// send ACK acknowledging client's seq
				ack := hdr{
					Ver:   1,
					Flags: FlagACK,
					Conn:  h.Conn,
					Win:   1024,
					Seq:   0,
					Ack:   h.Seq,
				}
				_, _ = sock.WriteToUDP(marshalHeader(ack), raddr)

				// then echo payload back as PSH
				payload := make([]byte, n-14)
				copy(payload, buf[14:n])
				pushHdr := hdr{
					Ver:   1,
					Flags: FlagPSH,
					Conn:  h.Conn,
					Win:   1024,
					Seq:   2000, // server seq
					Ack:   h.Seq,
				}
				out := append(marshalHeader(pushHdr), payload...)
				_, _ = sock.WriteToUDP(out, raddr)
				continue
			}
		}
	}()

	return sock.LocalAddr().String(), nil
}

func TestHandshakeAndSendReliable(t *testing.T) {
	// start mock server on ephemeral port
	stop := make(chan struct{})
	serverAddr, err := runMockServer(t, "127.0.0.1:0", stop)
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer close(stop)

	// create client UDP conn
	clientConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("client ListenUDP failed: %v", err)
	}
	defer clientConn.Close()

	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("resolve server addr failed: %v", err)
	}

	// test handshake
	connID := uint16(0x2000)
	if err := handshake(clientConn, raddr, connID); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// send reliable PSH and expect no error
	for i := 0; i < 3; i++ {
		seq := uint32(i + 1)
		// make random string payload
		payload := []byte("test-message")
		if err := sendReliable(clientConn, raddr, connID, seq, payload); err != nil {
			t.Fatalf("sendReliable failed: %v", err)
		}

		// Now wait for echo PSH from server
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65536)
		n, addr, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read echo failed: %v", err)
		}
		if addr.String() != raddr.String() {
			t.Fatalf("echo from unexpected addr: %s", addr.String())
		}
		h, err := unmarshalHeader(buf[:n])
		if err != nil {
			t.Fatalf("unmarshalHeader on echo failed: %v", err)
		}
		if h.Flags&FlagPSH == 0 {
			t.Fatalf("expected PSH flag in echo, got 0x%02x", h.Flags)
		}
		echoPayload := buf[14:n]
		if !bytes.Equal(echoPayload, payload) {
			t.Fatalf("echo payload mismatch: got %q want %q", string(echoPayload), string(payload))
		}
	}
}
