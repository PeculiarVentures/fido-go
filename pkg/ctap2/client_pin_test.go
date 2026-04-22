package ctap2_test

import (
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
