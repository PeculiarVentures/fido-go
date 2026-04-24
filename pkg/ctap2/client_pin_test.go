package ctap2_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/fxamacker/cbor/v2"
)

func TestClientPINCommandEncodeDecode(t *testing.T) {
	t.Parallel()

	command := ctap2.NewClientPINGetRetriesCommand(1)
	encoded, err := command.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[0] != ctap2.CommandClientPIN {
		t.Fatalf("unexpected command byte: 0x%02x", encoded[0])
	}

	payload, err := cbor.Marshal(map[uint64]any{3: uint64(8), 4: true})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var response ctap2.ClientPINResponse
	err = command.DecodeResponse(append([]byte{0x00}, payload...), &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.PINRetries != 8 {
		t.Fatalf("unexpected retries: %d", response.PINRetries)
	}
	if !response.PowerCycleState {
		t.Fatal("expected powerCycleState=true")
	}
}

func TestClientPINCommandEncodeRejectsInvalidKeyAgreement(t *testing.T) {
	t.Parallel()

	command := ctap2.NewClientPINCommand(1, ctap2.ClientPINSetPIN)
	command.KeyAgreement = &ctap2.COSEKey{KeyType: ctap2.COSEKeyTypeEC2}

	if _, err := command.Encode(); err == nil {
		t.Fatal("expected key agreement validation error")
	}
}

func TestClientPINCommandDecodeResponseWithKeyAgreement(t *testing.T) {
	t.Parallel()

	payload, err := cbor.Marshal(map[uint64]any{
		1: map[int64]any{
			1:  int64(ctap2.COSEKeyTypeEC2),
			3:  int64(ctap2.COSEAlgorithmECDHESHKDF256),
			-1: int64(ctap2.COSECurveP256),
			-2: bytes.Repeat([]byte{0x11}, 32),
			-3: bytes.Repeat([]byte{0x22}, 32),
		},
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var response ctap2.ClientPINResponse
	err = ctap2.NewClientPINCommand(1, ctap2.ClientPINGetKeyAgreement).DecodeResponse(append([]byte{0x00}, payload...), &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.KeyAgreement == nil || len(response.KeyAgreement.X) != 32 || len(response.KeyAgreement.Y) != 32 {
		t.Fatalf("unexpected key agreement: %#v", response.KeyAgreement)
	}
}
