package client

import (
	"fmt"
	codec "icmp-tunnel/pkg"
	"net"
	"os"
	"time"
)

func Client(serverIP string, localUDP string) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", localUDP)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()

	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return icmpConn, nil
}

func SendData(con net.PacketConn, serverIP string, data []byte) ([]byte, error) {
	// defer con.Close()
	var secretKey = []byte("0123456789abcdef")
	data, err := codec.EncryptAES(secretKey, data)
	if err != nil {
		return nil, err
	}

	session := uint16(os.Getpid() & 0xffff)
	seq := uint16(1)
	frags, err := codec.SimpleFragment(session, seq, data, 1400)
	if err != nil {
		return nil, err
	}

	icmpID := session
	icmpSeq := seq
	for _, frag := range frags {
		pkt := codec.BuildICMPEcho(8, 0, icmpID, icmpSeq, frag)
		sendConn, err := net.Dial("ip4:icmp", serverIP)
		if err != nil {
			return nil, err
		}
		sendConn.Write(pkt)
		sendConn.Close()
	}

	reasm := codec.NewReassembler(5 * time.Second)
	timeout := time.After(3 * time.Second)
	buf := make([]byte, 65535)

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response")
		default:
			n, _, err := con.ReadFrom(buf)
			if err != nil {
				continue
			}
			typ, _, _, _, payload, err := codec.ParseICMPEcho(buf[:n])
			if err != nil || typ != 0 {
				continue
			}
			sess, s, idx, total, data, err := codec.ParseFragmentPayload(payload)
			if err != nil || sess != session || s != seq {
				continue
			}
			complete, assembled, err := reasm.AddFragment(sess, s, idx, total, data)
			if err == nil && complete {
				assembled, err = codec.DecryptAES(secretKey, assembled)
				if err != nil {
					return nil, err
				}
				return assembled, nil
			}
		}
	}
}
