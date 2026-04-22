package ctap1_test

import (
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
)

func TestVersionCommandEncode(t *testing.T) {
	t.Parallel()

	encoded, err := ctap1.NewVersionCommand().Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := []byte{0x00, 0x03, 0x00, 0x00, 0x00}
	if string(encoded) != string(want) {
		t.Fatalf("encoded mismatch: got % X want % X", encoded, want)
	}
}

func TestVersionCommandDecodeResponse(t *testing.T) {
	t.Parallel()

	var response ctap1.VersionResponse
	err := ctap1.NewVersionCommand().DecodeResponse([]byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0x00}, &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Version != "U2F_V2" {
		t.Fatalf("version mismatch: got %q", response.Version)
	}
}

func TestVersionCommandDecodeResponseStatusError(t *testing.T) {
	t.Parallel()

	var response ctap1.VersionResponse
	err := ctap1.NewVersionCommand().DecodeResponse([]byte{0x69, 0x85}, &response)
	var statusErr *ctap1.Error
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected ctap1.Error, got %v", err)
	}
	if statusErr.StatusWord != 0x6985 {
		t.Fatalf("status mismatch: got 0x%04x", statusErr.StatusWord)
	}
}
