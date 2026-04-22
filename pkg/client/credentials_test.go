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

type handlerSession struct {
	device  transport.DeviceDescriptor
	handler func(context.Context, []byte) ([]byte, error)
}

func (session *handlerSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *handlerSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	return session.handler(ctx, req)
}

func (session *handlerSession) Close() error {
	return nil
}

func TestClientListCredentialsUsesCredentialManagement(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	pin := "123456"
	pinHash := sha256.Sum256([]byte(pin))
	pinToken := bytes.Repeat([]byte{0x11}, 32)
	rpIDHash := bytes.Repeat([]byte{0x22}, 32)

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"clientPin": true, "credMgmt": true},
					PinUVAuthProtocols: []uint64{1},
					Transports:         []string{"usb"},
				}), nil
			case ctap2.CommandClientPIN:
				return handleClientPINRequest(t, authenticatorKey, authenticatorPublic, pinHash[:16], pinToken, req[1:]), nil
			case ctap2.CommandCredentialManagement:
				return handleCredentialManagementRequest(t, pinToken, rpIDHash, req[1:]), nil
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

	result, err := candidate.ListCredentials(context.Background(), pin)
	if err != nil {
		t.Fatalf("ListCredentials() error = %v", err)
	}
	if result.ExistingResidentCredentialsCount != 2 {
		t.Fatalf("ExistingResidentCredentialsCount = %d, want 2", result.ExistingResidentCredentialsCount)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("len(Credentials) = %d, want 2", len(result.Credentials))
	}
	if got := result.Credentials[0].RP.ID; got != "example.com" {
		t.Fatalf("first RP = %q, want example.com", got)
	}
	if got := result.Credentials[1].User.Name; got != "bob" {
		t.Fatalf("second user = %q, want bob", got)
	}
}

func handleClientPINRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, pinHash []byte, pinToken []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64           `cbor:"1,keyasint,omitempty"`
		Subcommand        uint64           `cbor:"2,keyasint"`
		KeyAgreement      map[int64]any    `cbor:"3,keyasint,omitempty"`
		PINHashEnc        []byte           `cbor:"6,keyasint,omitempty"`
		Permissions       ctap2.Permission `cbor:"9,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN) error = %v", err)
	}

	switch request.Subcommand {
	case uint64(ctap2.ClientPINGetKeyAgreement):
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: map[int64]any{
			1:  int64(2),
			3:  int64(-25),
			-1: int64(1),
			-2: append([]byte(nil), authenticatorPublic[1:33]...),
			-3: append([]byte(nil), authenticatorPublic[33:65]...),
		}})
	case uint64(ctap2.ClientPINGetPINTokenWithPIN):
		platformKey, err := coseEC2PublicKey(request.KeyAgreement)
		if err != nil {
			t.Fatalf("coseEC2PublicKey() error = %v", err)
		}
		sharedPoint, err := authenticatorKey.ECDH(platformKey)
		if err != nil {
			t.Fatalf("ECDH() error = %v", err)
		}
		sharedSecret := sha256.Sum256(sharedPoint)
		decryptedPINHash, err := pinProtocol1Decrypt(sharedSecret[:], request.PINHashEnc)
		if err != nil {
			t.Fatalf("pinProtocol1Decrypt() error = %v", err)
		}
		if !bytes.Equal(decryptedPINHash, pinHash) {
			t.Fatalf("decrypted PIN hash = %x, want %x", decryptedPINHash, pinHash)
		}
		if request.Permissions != ctap2.PermissionCredentialManagement {
			t.Fatalf("Permissions = %d, want %d", request.Permissions, ctap2.PermissionCredentialManagement)
		}
		encryptedToken, err := pinProtocol1Encrypt(sharedSecret[:], pinToken)
		if err != nil {
			t.Fatalf("pinProtocol1Encrypt() error = %v", err)
		}
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{PinUVAuthToken: encryptedToken})
	default:
		t.Fatalf("unexpected ClientPIN subcommand %d", request.Subcommand)
		return nil
	}
}

func handleCredentialManagementRequest(t *testing.T, pinToken []byte, rpIDHash []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		Subcommand        uint64                                      `cbor:"1,keyasint"`
		SubcommandParams  *ctap2.CredentialManagementSubcommandParams `cbor:"2,keyasint,omitempty"`
		PinUVAuthProtocol uint64                                      `cbor:"3,keyasint,omitempty"`
		PinUVAuthParam    []byte                                      `cbor:"4,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(credentialManagement) error = %v", err)
	}

	assertAuth := func(subcommand ctap2.CredentialManagementSubcommand, params *ctap2.CredentialManagementSubcommandParams) {
		command := ctap2.NewCredentialManagementCommand(ctap2.CommandCredentialManagement, subcommand)
		command.SubcommandParams = params
		expected, err := pinProtocol1AuthParam(pinToken, command)
		if err != nil {
			t.Fatalf("pinProtocol1AuthParam() error = %v", err)
		}
		if !bytes.Equal(request.PinUVAuthParam, expected) {
			t.Fatalf("PinUVAuthParam = %x, want %x", request.PinUVAuthParam, expected)
		}
	}

	switch request.Subcommand {
	case uint64(ctap2.CredentialManagementGetMetadata):
		assertAuth(ctap2.CredentialManagementGetMetadata, nil)
		return encodeCTAP2Success(t, ctap2.CredentialManagementResponse{
			ExistingResidentCredentialsCount:             2,
			MaxPossibleRemainingResidentCredentialsCount: 23,
		})
	case uint64(ctap2.CredentialManagementEnumerateRPsBegin):
		assertAuth(ctap2.CredentialManagementEnumerateRPsBegin, nil)
		return encodeCTAP2Success(t, ctap2.CredentialManagementResponse{
			RP:       &ctap2.RelyingPartyEntity{ID: "example.com", Name: "Example"},
			RPIDHash: append([]byte(nil), rpIDHash...),
			TotalRPs: 1,
		})
	case uint64(ctap2.CredentialManagementEnumerateCredentialsBegin):
		params := &ctap2.CredentialManagementSubcommandParams{RPIDHash: append([]byte(nil), rpIDHash...)}
		assertAuth(ctap2.CredentialManagementEnumerateCredentialsBegin, params)
		if request.SubcommandParams == nil || !bytes.Equal(request.SubcommandParams.RPIDHash, rpIDHash) {
			t.Fatalf("unexpected RPIDHash params %#v", request.SubcommandParams)
		}
		return encodeCTAP2Success(t, ctap2.CredentialManagementResponse{
			User:             &ctap2.UserEntity{ID: []byte{0x01}, Name: "alice", DisplayName: "Alice"},
			CredentialID:     &ctap2.CredentialDescriptor{Type: "public-key", ID: []byte{0xaa}},
			TotalCredentials: 2,
		})
	case uint64(ctap2.CredentialManagementEnumerateCredentialsGetNext):
		return encodeCTAP2Success(t, ctap2.CredentialManagementResponse{
			User:         &ctap2.UserEntity{ID: []byte{0x02}, Name: "bob", DisplayName: "Bob"},
			CredentialID: &ctap2.CredentialDescriptor{Type: "public-key", ID: []byte{0xbb}},
		})
	default:
		t.Fatalf("unexpected credential management subcommand %d", request.Subcommand)
		return nil
	}
}

func encodeCTAP2Success(t *testing.T, payload any) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}
	return append([]byte{0x00}, encoded...)
}
