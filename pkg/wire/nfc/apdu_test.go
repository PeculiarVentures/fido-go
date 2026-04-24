package nfc_test

import (
	"bytes"
	"errors"
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

func TestAssemblerReturnsStatusError(t *testing.T) {
	t.Parallel()

	codec, err := nfc.NewCodec(0x80, 0x10, 0x00, 0x00, 8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	assembler := codec.NewAssembler()
	err = assembler.Add([]byte{0x6A, 0x82})
	var statusErr *nfc.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Add() error = %v, want StatusError", err)
	}
	if statusErr.SW1 != 0x6A || statusErr.SW2 != 0x82 {
		t.Fatalf("status = 0x%02x%02x, want 0x6a82", statusErr.SW1, statusErr.SW2)
	}
}

func TestValidateInterimResponseReturnsStatusError(t *testing.T) {
	t.Parallel()

	codec, err := nfc.NewCodec(0x80, 0x10, 0x00, 0x00, 8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	err = codec.ValidateInterimResponse([]byte{0x69, 0x85})
	var statusErr *nfc.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("ValidateInterimResponse() error = %v, want StatusError", err)
	}
	if statusErr.SW1 != 0x69 || statusErr.SW2 != 0x85 {
		t.Fatalf("status = 0x%02x%02x, want 0x6985", statusErr.SW1, statusErr.SW2)
	}
}
