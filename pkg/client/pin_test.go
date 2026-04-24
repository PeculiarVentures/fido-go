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

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	if err := ctap2Candidate.PIN().Change(context.Background(), NewSecretString(currentPIN), NewSecretString(newPIN)); err != nil {
		t.Fatalf("PIN().Change() error = %v", err)
	}
	if changeRequests != 1 {
		t.Fatalf("changeRequests = %d, want 1", changeRequests)
	}
}

func TestClientSetPIN(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	newPIN := "87654321"
	setRequests := 0

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"clientPin": false},
					PinUVAuthProtocols: []uint64{1},
				}), nil
			case ctap2.CommandClientPIN:
				response, set := handleClientPINSetRequest(t, authenticatorKey, authenticatorPublic, newPIN, req[1:])
				if set {
					setRequests++
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

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	if err := ctap2Candidate.PIN().Set(context.Background(), NewSecretString(newPIN)); err != nil {
		t.Fatalf("PIN().Set() error = %v", err)
	}
	if setRequests != 1 {
		t.Fatalf("setRequests = %d, want 1", setRequests)
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

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	status, err := ctap2Candidate.PIN().Status(context.Background())
	if err != nil {
		t.Fatalf("PIN().Status() error = %v", err)
	}
	if !status.Configured {
		t.Fatal("Configured = false, want true")
	}
	if status.Retries != 8 {
		t.Fatalf("Retries = %d, want 8", status.Retries)
	}
	if status.UVRetries != 5 {
		t.Fatalf("UVRetries = %d, want 5", status.UVRetries)
	}
	if !status.PowerCycleNeeded {
		t.Fatal("PowerCycleNeeded = false, want true")
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

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	if err := ctap2Candidate.PIN().Change(context.Background(), NewSecretString(currentPIN), NewSecretString(newPIN)); err != nil {
		t.Fatalf("PIN().Change() error = %v", err)
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
		KeyAgreement      *ctap2.COSEKey            `cbor:"3,keyasint,omitempty"`
		PinUVAuthParam    []byte                    `cbor:"4,keyasint,omitempty"`
		NewPINEnc         []byte                    `cbor:"5,keyasint,omitempty"`
		PINHashEnc        []byte                    `cbor:"6,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN change) error = %v", err)
	}

	switch request.Subcommand {
	case ctap2.ClientPINGetKeyAgreement:
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: &ctap2.COSEKey{
			KeyType:   ctap2.COSEKeyTypeEC2,
			Algorithm: ctap2.COSEAlgorithmECDHESHKDF256,
			Curve:     ctap2.COSECurveP256,
			X:         append([]byte(nil), authenticatorPublic[1:33]...),
			Y:         append([]byte(nil), authenticatorPublic[33:65]...),
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

func handleClientPINSetRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, newPIN string, payload []byte) ([]byte, bool) {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64                    `cbor:"1,keyasint,omitempty"`
		Subcommand        ctap2.ClientPINSubcommand `cbor:"2,keyasint"`
		KeyAgreement      *ctap2.COSEKey            `cbor:"3,keyasint,omitempty"`
		PinUVAuthParam    []byte                    `cbor:"4,keyasint,omitempty"`
		NewPINEnc         []byte                    `cbor:"5,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN set) error = %v", err)
	}

	switch request.Subcommand {
	case ctap2.ClientPINGetKeyAgreement:
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: &ctap2.COSEKey{
			KeyType:   ctap2.COSEKeyTypeEC2,
			Algorithm: ctap2.COSEAlgorithmECDHESHKDF256,
			Curve:     ctap2.COSECurveP256,
			X:         append([]byte(nil), authenticatorPublic[1:33]...),
			Y:         append([]byte(nil), authenticatorPublic[33:65]...),
		}}), false
	case ctap2.ClientPINSetPIN:
		platformPublic, err := coseEC2PublicKey(request.KeyAgreement)
		if err != nil {
			t.Fatalf("coseEC2PublicKey() error = %v", err)
		}
		sharedSecret, err := authenticatorKey.ECDH(platformPublic)
		if err != nil {
			t.Fatalf("ECDH() error = %v", err)
		}
		hashedSecret := sha256.Sum256(sharedSecret)
		if expected := pinProtocol1Authenticate(hashedSecret[:], request.NewPINEnc); !bytes.Equal(request.PinUVAuthParam, expected) {
			t.Fatalf("PinUVAuthParam = %x, want %x", request.PinUVAuthParam, expected)
		}
		decryptedNewPIN, err := pinProtocol1Decrypt(hashedSecret[:], request.NewPINEnc)
		if err != nil {
			t.Fatalf("pinProtocol1Decrypt(newPinEnc) error = %v", err)
		}
		if len(decryptedNewPIN) != clientPINPaddedLength {
			t.Fatalf("len(decryptedNewPIN) = %d, want %d", len(decryptedNewPIN), clientPINPaddedLength)
		}
		if got := string(bytes.TrimRight(decryptedNewPIN, "\x00")); got != newPIN {
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
