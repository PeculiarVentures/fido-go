package ctap1_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
)

func TestAuthenticateCommandEncode(t *testing.T) {
	t.Parallel()

	challenge := bytes.Repeat([]byte{0x11}, 32)
	application := bytes.Repeat([]byte{0x22}, 32)
	keyHandle := []byte{0xAA, 0xBB, 0xCC}

	encoded, err := ctap1.NewAuthenticateCommand(ctap1.ControlEnforceUserPresenceAndSign, challenge, application, keyHandle).Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	wantPrefix := []byte{0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x44}
	if !bytes.Equal(encoded[:7], wantPrefix) {
		t.Fatalf("prefix mismatch: got % X want % X", encoded[:7], wantPrefix)
	}
	if !bytes.Equal(encoded[7:39], challenge) {
		t.Fatal("challenge bytes mismatch")
	}
	if !bytes.Equal(encoded[39:71], application) {
		t.Fatal("application bytes mismatch")
	}
	if encoded[71] != byte(len(keyHandle)) {
		t.Fatalf("key handle length mismatch: %d", encoded[71])
	}
	if !bytes.Equal(encoded[72:75], keyHandle) {
		t.Fatal("key handle bytes mismatch")
	}
	if !bytes.Equal(encoded[len(encoded)-2:], []byte{0x00, 0x00}) {
		t.Fatalf("extended Le mismatch: got % X", encoded[len(encoded)-2:])
	}
}

func TestAuthenticateCommandDecodeResponse(t *testing.T) {
	t.Parallel()

	payload := []byte{0x01, 0x00, 0x00, 0x00, 0x09, 0x30, 0x05, 0x02, 0x01, 0x01}
	responseBytes := append(payload, 0x90, 0x00)

	var response ctap1.AuthenticateResponse
	err := ctap1.NewAuthenticateCommand(ctap1.ControlEnforceUserPresenceAndSign, bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), []byte{0xAA}).DecodeResponse(responseBytes, &response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.UserPresent() {
		t.Fatal("expected user presence flag to be set")
	}
	if response.Counter != 9 {
		t.Fatalf("counter mismatch: %d", response.Counter)
	}
	if !bytes.Equal(response.Signature, payload[5:]) {
		t.Fatal("signature mismatch")
	}
}
