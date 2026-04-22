package ctap1_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
)

func TestRegisterCommandEncode(t *testing.T) {
	t.Parallel()

	challenge := bytes.Repeat([]byte{0x11}, 32)
	application := bytes.Repeat([]byte{0x22}, 32)

	encoded, err := ctap1.NewRegisterCommand(challenge, application).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if len(encoded) != 73 {
		t.Fatalf("unexpected APDU length: %d", len(encoded))
	}
	wantPrefix := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40}
	if !bytes.Equal(encoded[:7], wantPrefix) {
		t.Fatalf("prefix mismatch: got % X want % X", encoded[:7], wantPrefix)
	}
	if !bytes.Equal(encoded[7:39], challenge) {
		t.Fatal("challenge bytes mismatch")
	}
	if !bytes.Equal(encoded[39:71], application) {
		t.Fatal("application bytes mismatch")
	}
	if !bytes.Equal(encoded[len(encoded)-2:], []byte{0x00, 0x00}) {
		t.Fatalf("extended Le mismatch: got % X", encoded[len(encoded)-2:])
	}
}

func TestRegisterCommandDecodeResponse(t *testing.T) {
	t.Parallel()

	publicKey := append([]byte{0x04}, bytes.Repeat([]byte{0x44}, 64)...)
	keyHandle := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	certificate := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	signature := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	payload := append([]byte{0x05}, publicKey...)
	payload = append(payload, byte(len(keyHandle)))
	payload = append(payload, keyHandle...)
	payload = append(payload, certificate...)
	payload = append(payload, signature...)
	responseBytes := append(payload, 0x90, 0x00)

	var response ctap1.RegisterResponse
	err := ctap1.NewRegisterCommand(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)).DecodeResponse(responseBytes, &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.ReservedByte != 0x05 {
		t.Fatalf("reserved byte mismatch: 0x%02x", response.ReservedByte)
	}
	if !bytes.Equal(response.PublicKey, publicKey) {
		t.Fatal("public key mismatch")
	}
	if !bytes.Equal(response.KeyHandle, keyHandle) {
		t.Fatal("key handle mismatch")
	}
	if !bytes.Equal(response.AttestationCertificate, certificate) {
		t.Fatal("certificate mismatch")
	}
	if !bytes.Equal(response.Signature, signature) {
		t.Fatal("signature mismatch")
	}
}
