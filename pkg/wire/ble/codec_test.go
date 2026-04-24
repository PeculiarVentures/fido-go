package ble_test

import (
	"bytes"
	"errors"
	"math"
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

func TestCodecRejectsPayloadTooLarge(t *testing.T) {
	t.Parallel()

	codec, err := ble.NewCodec(64)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	_, err = codec.Fragment(make([]byte, math.MaxUint16+1))
	if !errors.Is(err, ble.ErrPayloadTooLarge) {
		t.Fatalf("fragment error = %v, want ErrPayloadTooLarge", err)
	}
}

func TestAssemblerRejectsExtraFragmentAfterCompletion(t *testing.T) {
	t.Parallel()

	codec, err := ble.NewCodec(8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	fragments, err := codec.Fragment([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}

	assembler := codec.NewAssembler()
	for _, fragment := range fragments {
		if err := assembler.Add(fragment); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := assembler.Add([]byte{0x00}); err == nil {
		t.Fatal("expected invalid fragment error")
	}
}

func TestAssemblerReportsIncompletePayloadWhenFragmentsStopEarly(t *testing.T) {
	t.Parallel()

	codec, err := ble.NewCodec(8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	assembler := codec.NewAssembler()
	if err := assembler.Add([]byte{0x00, 0x04, 0x01, 0x02}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := assembler.Payload(); err == nil {
		t.Fatal("expected incomplete payload error")
	}
}
