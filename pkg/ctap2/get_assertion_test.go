package ctap2_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/fxamacker/cbor/v2"
)

func TestGetAssertionCommandEncodeDecode(t *testing.T) {
	t.Parallel()

	command := ctap2.NewGetAssertionCommand("example.com", bytes.Repeat([]byte{0x22}, 32))
	command.AllowList = []ctap2.CredentialDescriptor{{Type: "public-key", ID: []byte{0x01, 0x02}}}

	encoded, err := command.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[0] != ctap2.CommandGetAssertion {
		t.Fatalf("unexpected command byte: 0x%02x", encoded[0])
	}

	payload, err := cbor.Marshal(map[uint64]any{
		1: map[string]any{"type": "public-key", "id": []byte{0x01, 0x02}},
		2: []byte{0xAA, 0xBB},
		3: []byte{0xCC},
		5: uint64(1),
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var response ctap2.GetAssertionResponse
	err = command.DecodeResponse(append([]byte{0x00}, payload...), &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(response.Credential.ID, []byte{0x01, 0x02}) {
		t.Fatal("credential mismatch")
	}
}
