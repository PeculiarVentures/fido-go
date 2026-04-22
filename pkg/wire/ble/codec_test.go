package ble_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/wire/ble"
)

func TestCodecFragmentReassemble(t *testing.T) {
	t.Parallel()

	codec, err := ble.NewCodec(8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	payload := bytes.Repeat([]byte{0x42}, 21)
	fragments, err := codec.Fragment(payload)
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	if len(fragments) < 3 {
		t.Fatalf("expected multiple fragments, got %d", len(fragments))
	}

	assembler := codec.NewAssembler()
	for _, fragment := range fragments {
		if err := assembler.Add(fragment); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	decoded, err := assembler.Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("payload mismatch")
	}
}
