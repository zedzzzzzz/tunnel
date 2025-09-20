package tests

import (
	"net"
	"os"
	"testing"
	"time"

	"icmp-tunnel/icmp/client"
	"icmp-tunnel/icmp/server"
)

// simple UDP backend for testing
func startTestUDPBackend(port string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			request := buf[:n]
			response := append([]byte("ECHO: "), request...)
			// fmt.Println("UDP Backend received:", string(request))
			_, _ = conn.WriteToUDP(response, clientAddr)
		}
	}()
	return conn, nil
}

func TestE2ETunnel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must run as root for raw ICMP sockets")
	}

	backendPort := ":9001"
	serverTunnelIP := "127.0.0.1"

	_, err := startTestUDPBackend(backendPort)
	if err != nil {
		t.Fatalf("backend start failed: %v", err)
	}

	err = server.Server(serverTunnelIP + backendPort)
	if err != nil {
		t.Fatalf("tunnel server start failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	testPayload := []byte("Hello ")
	con, err := client.Client(serverTunnelIP, ":9000")
	if err != nil {
		t.Fatalf("Tunnel test failed: %v", err)
	}
	resp, err := client.SendData(con, serverTunnelIP, testPayload)
	if err != nil {
		t.Fatalf("Tunnel test failed: %v", err)
	}
	if string(resp) != string(testPayload) {
		t.Fatalf("Unexpected response: %s", string(resp))
	}

	resp, err = client.SendData(con, serverTunnelIP, testPayload)
	if err != nil {
		t.Fatalf("Tunnel test failed: %v", err)
	}
	if string(resp) != string(testPayload) {
		t.Fatalf("Unexpected response: %s", string(resp))
	}
}
