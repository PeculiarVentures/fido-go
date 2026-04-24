package hid_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func TestCodecFragmentReassemble(t *testing.T) {
	t.Parallel()

	codec, err := hid.NewCodec(0x01020304, 0x90, 16)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	payload := bytes.Repeat([]byte{0xAB}, 40)
	packets, err := codec.Fragment(payload)
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	if len(packets) < 3 {
		t.Fatalf("expected fragmented payload, got %d packet(s)", len(packets))
	}

	assembler := codec.NewAssembler()
	for _, packet := range packets {
		if err := assembler.Add(packet); err != nil {
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

func TestAssemblerRejectsSequenceGap(t *testing.T) {
	t.Parallel()

	codec, err := hid.NewCodec(0x01020304, 0x90, 16)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	packets, err := codec.Fragment(bytes.Repeat([]byte{0xCD}, 40))
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	packets[1][4] = 0x02

	assembler := codec.NewAssembler()
	if err := assembler.Add(packets[0]); err != nil {
		t.Fatalf("add initial: %v", err)
	}
	if err := assembler.Add(packets[1]); err == nil {
		t.Fatal("expected sequence error")
	}
}

func TestCodecRejectsPayloadTooLarge(t *testing.T) {
	t.Parallel()

	codec, err := hid.NewCodec(0x01020304, 0x90, 64)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}

	_, err = codec.Fragment(bytes.Repeat([]byte{0xAB}, 7610))
	if !errors.Is(err, hid.ErrPayloadTooLarge) {
		t.Fatalf("fragment error = %v, want ErrPayloadTooLarge", err)
	}
}
