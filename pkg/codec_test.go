package pkg

import (
	"bytes"
	"testing"
	"time"
)

func TestFragmentReassemble(t *testing.T) {
	data := []byte("Hello, this is a test payload for fragmenting and reassembling!")
	session := uint16(1234)
	seq := uint16(1)
	maxLen := 10

	// split into fragments
	frags, err := SimpleFragment(session, seq, data, maxLen)
	if err != nil {
		t.Fatalf("SimpleFragment failed: %v", err)
	}

	r := NewReassembler(2 * time.Second)
	var assembled []byte
	var complete bool

	// shuffle fragments to simulate out-of-order arrival
	for i := len(frags) - 1; i >= 0; i-- {
		c, a, err := r.AddFragment(session, seq, frags[i][4], frags[i][5], frags[i][6:])
		if err != nil && err != ErrIncompleteFragment {
			t.Fatalf("AddFragment failed: %v", err)
		}
		if c {
			complete = true
			assembled = a
		}
	}

	if !complete {
		t.Fatal("Reassembler did not complete")
	}

	if !bytes.Equal(data, assembled) {
		t.Fatalf("Assembled data does not match original.\nGot: %s\nWant: %s", assembled, data)
	}
}

func TestFragmentPayloadTooShort(t *testing.T) {
	_, _, _, _, _, err := ParseFragmentPayload([]byte{0, 1, 2})
	if err == nil {
		t.Fatal("Expected error for short fragment, got nil")
	}
}

func TestICMPEchoBuildParse(t *testing.T) {
	payload := []byte("ping test")
	id := uint16(42)
	seq := uint16(7)

	pkt := BuildICMPEcho(8, 0, id, seq, payload)
	typ, code, pid, pse, pl, err := ParseICMPEcho(pkt)
	if err != nil {
		t.Fatalf("ParseICMPEcho failed: %v", err)
	}
	if typ != 8 || code != 0 || pid != id || pse != seq || !bytes.Equal(pl, payload) {
		t.Fatalf("Parse mismatch. Got typ=%d code=%d id=%d seq=%d payload=%s", typ, code, pid, pse, pl)
	}
}
