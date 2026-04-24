package ctap2_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/fxamacker/cbor/v2"
)

func TestMakeCredentialCommandEncodeDecode(t *testing.T) {
	t.Parallel()

	command := ctap2.NewMakeCredentialCommand(
		bytes.Repeat([]byte{0x11}, 32),
		ctap2.RelyingPartyEntity{ID: "example.com", Name: "Example"},
		ctap2.UserEntity{ID: []byte{0x01}, Name: "alice", DisplayName: "Alice"},
		[]ctap2.CredentialParameter{{Type: "public-key", Alg: -7}},
	)
	command.Options = &ctap2.MakeCredentialOptions{ResidentKey: true}

	encoded, err := command.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[0] != ctap2.CommandMakeCredential {
		t.Fatalf("unexpected command byte: 0x%02x", encoded[0])
	}
	canonicalCredentialParameter := []byte{0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'}
	if !bytes.Contains(encoded, canonicalCredentialParameter) {
		t.Fatalf("encoded makeCredential request does not use CTAP2 canonical CBOR for pubKeyCredParams: %x", encoded)
	}

	payload, err := cbor.Marshal(map[uint64]any{
		1: "packed",
		2: []byte{0xAA, 0xBB},
		3: map[string]any{"sig": []byte{0x01}},
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var response ctap2.MakeCredentialResponse
	err = command.DecodeResponse(append([]byte{0x00}, payload...), &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Format != "packed" {
		t.Fatalf("unexpected format: %q", response.Format)
	}
}
