package server

import (
	"fmt"
	codec "icmp-tunnel/pkg"
	"net"
	"time"
)

func Server(udpTarget string) error {
	var secretKey = []byte("0123456789abcdef")

	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("listen icmp failed: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", udpTarget)
	if err != nil {
		return fmt.Errorf("resolve udp target failed: %v", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp failed: %v", err)
	}
	// _, err = udpConn.Write(assembled)
	reasm := codec.NewReassembler(5 * time.Second)
	buf := make([]byte, 65535)

	go func() {
		for {
			n, addr, err := icmpConn.ReadFrom(buf)
			if err != nil {
				continue
			}

			typ, _, id, seq, payload, err := codec.ParseICMPEcho(buf[:n])
			if err != nil || typ != 8 {
				continue
			}

			session, seqNum, idx, total, data, err := codec.ParseFragmentPayload(payload)
			if err != nil {
				continue
			}

			complete, assembled, err := reasm.AddFragment(session, seqNum, idx, total, data)
			if err != nil || !complete {
				continue
			}
			//
			assembled, err = codec.DecryptAES(secretKey, assembled)
			if err != nil {
				continue // ignore if decryption failed
			}
			//
			_, err = udpConn.Write(assembled)
			if err != nil {
				continue
			}
			rbuf := make([]byte, 65535)
			udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			nr, _, err := udpConn.ReadFromUDP(rbuf)
			reply := []byte{}
			if err == nil {
				reply = rbuf[:nr]
			}
			frags, _ := codec.SimpleFragment(session, seqNum, reply, 1400)
			for _, frag := range frags {
				replyPkt := codec.BuildICMPEcho(0, 0, id, seq, frag)
				sendConn, err := net.Dial("ip4:icmp", addr.String())
				if err != nil {
					fmt.Println("Failed to dial icmp")
					continue
				}
				fmt.Println(replyPkt)
				fmt.Println("send")
				sendConn.Write(replyPkt)
				sendConn.Close()
			}
		}
	}()
	return nil
}
