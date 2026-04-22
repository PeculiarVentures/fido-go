package nfc_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/wire/nfc"
)

func TestCodecFragmentSetsChainBit(t *testing.T) {
	t.Parallel()

	codec, err := nfc.NewCodec(0x80, 0x10, 0x00, 0x00, 8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	packets, err := codec.Fragment(bytes.Repeat([]byte{0x01}, 12))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("unexpected packet count: %d", len(packets))
	}
	if packets[0][0]&0x10 == 0 {
		t.Fatal("expected chain bit on intermediate packet")
	}
	if packets[1][0]&0x10 != 0 {
		t.Fatal("did not expect chain bit on final packet")
	}
}

func TestAssemblerReassemblesResponseChain(t *testing.T) {
	t.Parallel()

	codec, err := nfc.NewCodec(0x80, 0x10, 0x00, 0x00, 8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	assembler := codec.NewAssembler()
	if err := assembler.Add([]byte{0xAA, 0xBB, 0x61, 0x02}); err != nil {
		t.Fatalf("add first response: %v", err)
	}
	if assembler.Done() {
		t.Fatal("response should not be complete")
	}
	if err := assembler.Add([]byte{0xCC, 0xDD, 0x90, 0x00}); err != nil {
		t.Fatalf("add final response: %v", err)
	}

	decoded, err := assembler.Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !bytes.Equal(decoded, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatal("payload mismatch")
	}
}
