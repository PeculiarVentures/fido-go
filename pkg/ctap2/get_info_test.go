package ctap2_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/fxamacker/cbor/v2"
)

func TestGetInfoCommandEncode(t *testing.T) {
	t.Parallel()

	encoded, err := ctap2.NewGetInfoCommand().Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := []byte{0x04}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded mismatch: got % X want % X", encoded, want)
	}
}

func TestGetInfoCommandDecodeResponse(t *testing.T) {
	t.Parallel()

	payload, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_1", "U2F_V2"},
		3: bytes.Repeat([]byte{0x11}, 16),
		4: map[string]bool{"clientPin": true},
		5: uint64(1200),
		9: []string{"usb", "nfc"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	responseBytes := append([]byte{0x00}, payload...)
	var response ctap2.GetInfoResponse
	err = ctap2.NewGetInfoCommand().DecodeResponse(responseBytes, &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(response.Versions) != 2 || response.Versions[0] != "FIDO_2_1" {
		t.Fatalf("unexpected versions: %#v", response.Versions)
	}
	if !response.Options["clientPin"] {
		t.Fatalf("expected clientPin option in %#v", response.Options)
	}
	if response.MaxMsgSize != 1200 {
		t.Fatalf("unexpected max message size: %d", response.MaxMsgSize)
	}
	if len(response.Transports) != 2 {
		t.Fatalf("unexpected transports: %#v", response.Transports)
	}
}

func TestGetInfoCommandDecodeResponseStatusError(t *testing.T) {
	t.Parallel()

	var response ctap2.GetInfoResponse
	err := ctap2.NewGetInfoCommand().DecodeResponse([]byte{0x01}, &response)
	var statusErr *ctap2.Error
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected ctap2.Error, got %v", err)
	}
	if statusErr.Code != 0x01 {
		t.Fatalf("unexpected status code: 0x%02x", statusErr.Code)
	}
}
