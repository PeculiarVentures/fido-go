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

func TestGetInfoCommandDecodeResponsePreservesExtendedFieldsAndRaw(t *testing.T) {
	t.Parallel()

	payload, err := cbor.Marshal(map[uint64]any{
		1:  []string{"FIDO_2_3", "U2F_V2"},
		3:  bytes.Repeat([]byte{0x11}, 16),
		4:  map[string]bool{"clientPin": true, "credMgmt": true},
		6:  []uint64{2, 1},
		9:  []string{"usb", "nfc"},
		10: []ctap2.CredentialParameter{{Type: "public-key", Alg: -7}},
		11: uint64(2048),
		12: true,
		13: uint64(6),
		14: uint64(42),
		15: uint64(64),
		16: uint64(8),
		17: uint64(2),
		18: uint64(1),
		19: map[string]uint64{"fido": 2},
		20: uint64(11),
		21: []uint64{0x40},
		64: []byte{0xAA, 0xBB},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var response ctap2.GetInfoResponse
	err = ctap2.NewGetInfoCommand().DecodeResponse(append([]byte{0x00}, payload...), &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Algorithms) != 1 || response.Algorithms[0].Alg != -7 {
		t.Fatalf("unexpected algorithms: %#v", response.Algorithms)
	}
	if response.MaxSerializedLargeBlobArray != 2048 || !response.ForcePINChange || response.MinPINLength != 6 {
		t.Fatalf("unexpected large blob or PIN policy fields: %#v", response)
	}
	if response.MaxCredBlobLength != 64 || response.PreferredPlatformUVAttempts != 2 || response.RemainingDiscoverableCredentials != 11 {
		t.Fatalf("unexpected extended fields: %#v", response)
	}
	if len(response.VendorPrototypeConfigCommands) != 1 || response.VendorPrototypeConfigCommands[0] != 0x40 {
		t.Fatalf("unexpected vendor commands: %#v", response.VendorPrototypeConfigCommands)
	}
	if _, ok := response.Raw[64]; !ok {
		t.Fatalf("expected unknown raw field to be preserved: %#v", response.Raw)
	}
	originalRaw := append([]byte(nil), response.Raw[64]...)
	clone := response.Clone()
	clone.Raw[64][0] = 0x00
	if !bytes.Equal(response.Raw[64], originalRaw) {
		t.Fatal("expected raw map to be cloned defensively")
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
