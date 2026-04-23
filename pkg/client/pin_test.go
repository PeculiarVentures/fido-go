package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/fxamacker/cbor/v2"
)

func TestClientChangePIN(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	currentPIN := "12345678"
	newPIN := "87654321"
	currentPINHash := sha256.Sum256([]byte(currentPIN))
	changeRequests := 0

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"clientPin": true},
					PinUVAuthProtocols: []uint64{1},
				}), nil
			case ctap2.CommandClientPIN:
				response, changed := handleClientPINChangeRequest(t, authenticatorKey, authenticatorPublic, currentPINHash[:16], newPIN, req[1:])
				if changed {
					changeRequests++
				}
				return response, nil
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := candidate.ChangePIN(context.Background(), currentPIN, newPIN); err != nil {
		t.Fatalf("ChangePIN() error = %v", err)
	}
	if changeRequests != 1 {
		t.Fatalf("changeRequests = %d, want 1", changeRequests)
	}
}

func TestClientGetPINRetries(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"clientPin": true},
					PinUVAuthProtocols: []uint64{1},
				}), nil
			case ctap2.CommandClientPIN:
				return handleClientPINRetriesRequest(t, authenticatorPublic, req[1:])
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	retries, err := candidate.GetPINRetries(context.Background())
	if err != nil {
		t.Fatalf("GetPINRetries() error = %v", err)
	}
	if retries.PINRetries != 8 {
		t.Fatalf("PINRetries = %d, want 8", retries.PINRetries)
	}
	if retries.UVRetries != 5 {
		t.Fatalf("UVRetries = %d, want 5", retries.UVRetries)
	}
	if !retries.PowerCycleState {
		t.Fatal("PowerCycleState = false, want true")
	}
}

func TestClientChangePINRetriesTransientInvalidCBOR(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	currentPIN := "12345678"
	newPIN := "87654321"
	currentPINHash := sha256.Sum256([]byte(currentPIN))
	changeRequests := 0

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindNFC, Product: "SafeNet"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"clientPin": true},
					PinUVAuthProtocols: []uint64{1},
				}), nil
			case ctap2.CommandClientPIN:
				response, changed := handleClientPINChangeRequest(t, authenticatorKey, authenticatorPublic, currentPINHash[:16], newPIN, req[1:])
				if changed {
					changeRequests++
					if changeRequests < 3 {
						return []byte{0x12}, nil
					}
				}
				return response, nil
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := candidate.ChangePIN(context.Background(), currentPIN, newPIN); err != nil {
		t.Fatalf("ChangePIN() error = %v", err)
	}
	if changeRequests != 3 {
		t.Fatalf("changeRequests = %d, want 3", changeRequests)
	}
}

func handleClientPINChangeRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, currentPINHash []byte, newPIN string, payload []byte) ([]byte, bool) {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64                    `cbor:"1,keyasint,omitempty"`
		Subcommand        ctap2.ClientPINSubcommand `cbor:"2,keyasint"`
		KeyAgreement      map[int64]any             `cbor:"3,keyasint,omitempty"`
		PinUVAuthParam    []byte                    `cbor:"4,keyasint,omitempty"`
		NewPINEnc         []byte                    `cbor:"5,keyasint,omitempty"`
		PINHashEnc        []byte                    `cbor:"6,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN change) error = %v", err)
	}

	switch request.Subcommand {
	case ctap2.ClientPINGetKeyAgreement:
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: map[int64]any{
			1:  int64(2),
			3:  int64(-25),
			-1: int64(1),
			-2: append([]byte(nil), authenticatorPublic[1:33]...),
			-3: append([]byte(nil), authenticatorPublic[33:65]...),
		}}), false
	case ctap2.ClientPINChangePIN:
		platformPublic, err := coseEC2PublicKey(request.KeyAgreement)
		if err != nil {
			t.Fatalf("coseEC2PublicKey() error = %v", err)
		}
		sharedSecret, err := authenticatorKey.ECDH(platformPublic)
		if err != nil {
			t.Fatalf("ECDH() error = %v", err)
		}
		hashedSecret := sha256.Sum256(sharedSecret)
		authMessage := make([]byte, 0, len(request.NewPINEnc)+len(request.PINHashEnc))
		authMessage = append(authMessage, request.NewPINEnc...)
		authMessage = append(authMessage, request.PINHashEnc...)
		if expected := pinProtocol1Authenticate(hashedSecret[:], authMessage); !bytes.Equal(request.PinUVAuthParam, expected) {
			t.Fatalf("PinUVAuthParam = %x, want %x", request.PinUVAuthParam, expected)
		}
		decryptedPINHash, err := pinProtocol1Decrypt(hashedSecret[:], request.PINHashEnc)
		if err != nil {
			t.Fatalf("pinProtocol1Decrypt(pinHashEnc) error = %v", err)
		}
		if !bytes.Equal(decryptedPINHash, currentPINHash) {
			t.Fatalf("decrypted PIN hash = %x, want %x", decryptedPINHash, currentPINHash)
		}
		decryptedNewPIN, err := pinProtocol1Decrypt(hashedSecret[:], request.NewPINEnc)
		if err != nil {
			t.Fatalf("pinProtocol1Decrypt(newPinEnc) error = %v", err)
		}
		if len(decryptedNewPIN) != clientPINPaddedLength {
			t.Fatalf("len(decryptedNewPIN) = %d, want %d", len(decryptedNewPIN), clientPINPaddedLength)
		}
		unpadded := bytes.TrimRight(decryptedNewPIN, "\x00")
		if got := string(unpadded); got != newPIN {
			t.Fatalf("new PIN = %q, want %q", got, newPIN)
		}
		return []byte{0x00}, true
	default:
		t.Fatalf("unexpected ClientPIN subcommand %d", request.Subcommand)
		return nil, false
	}
}

func handleClientPINRetriesRequest(t *testing.T, authenticatorPublic []byte, payload []byte) ([]byte, error) {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64                    `cbor:"1,keyasint,omitempty"`
		Subcommand        ctap2.ClientPINSubcommand `cbor:"2,keyasint"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN retries) error = %v", err)
	}
	if request.PinUVAuthProtocol != 1 {
		t.Fatalf("PinUVAuthProtocol = %d, want 1", request.PinUVAuthProtocol)
	}
	if request.Subcommand != ctap2.ClientPINGetRetries {
		t.Fatalf("Subcommand = %d, want %d", request.Subcommand, ctap2.ClientPINGetRetries)
	}
	_ = authenticatorPublic
	return encodeCTAP2Success(t, ctap2.ClientPINResponse{
		PINRetries:      8,
		UVRetries:       5,
		PowerCycleState: true,
	}), nil
}
