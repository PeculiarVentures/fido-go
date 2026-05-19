package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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

type recordingPINInteractionHandler struct {
	pin      Secret
	events   []InteractionEvent
	requests []PINRequest
}

func (handler *recordingPINInteractionHandler) OnInteraction(_ context.Context, event InteractionEvent) {
	handler.events = append(handler.events, event)
}

func (handler *recordingPINInteractionHandler) RequestPIN(_ context.Context, request PINRequest) (Secret, error) {
	handler.requests = append(handler.requests, request)
	return handler.pin, nil
}

type failingInteractionHandler struct {
	t *testing.T
}

func (handler failingInteractionHandler) OnInteraction(_ context.Context, _ InteractionEvent) {}

func (handler failingInteractionHandler) RequestPIN(_ context.Context, request PINRequest) (Secret, error) {
	handler.t.Fatalf("unexpected PIN request: %#v", request)
	return nil, nil
}

func TestCredentialManagerResolveDefaultAuthorizationRequestsPIN(t *testing.T) {
	handler := &recordingPINInteractionHandler{pin: NewSecretString("123456")}
	manager := credentialManager{client: &client{
		session:     &handlerSession{device: transport.DeviceDescriptor{ID: "device-default", Transport: transport.KindUSB}},
		interaction: handler,
	}}

	resolved, err := manager.resolveCredentialAuthorization(context.Background(), DefaultUVAuthorization(), "list credentials", "Enter PIN")
	if err != nil {
		t.Fatalf("resolveCredentialAuthorization() error = %v", err)
	}
	if resolved.Method != VerificationMethodPIN {
		t.Fatalf("Method = %q, want %q", resolved.Method, VerificationMethodPIN)
	}
	if !bytes.Equal(resolved.PIN, []byte("123456")) {
		t.Fatalf("PIN = %q, want 123456", string(resolved.PIN))
	}
	if len(handler.requests) != 1 {
		t.Fatalf("PIN requests = %d, want 1", len(handler.requests))
	}
	if got := handler.requests[0].Operation; got != "list credentials" {
		t.Fatalf("PIN request operation = %q, want list credentials", got)
	}
	if got := handler.requests[0].Method; got != VerificationMethodPIN {
		t.Fatalf("PIN request method = %q, want %q", got, VerificationMethodPIN)
	}
	if len(handler.events) != 1 || handler.events[0].Kind != InteractionAwaitingPIN {
		t.Fatalf("interaction events = %#v, want one awaiting-pin event", handler.events)
	}
}

func TestCredentialManagerResolveExplicitPINAuthorization(t *testing.T) {
	manager := credentialManager{client: &client{interaction: failingInteractionHandler{t: t}}}

	resolved, err := manager.resolveCredentialAuthorization(context.Background(), PINAuthorization("654321"), "list credentials", "Enter PIN")
	if err != nil {
		t.Fatalf("resolveCredentialAuthorization() error = %v", err)
	}
	if resolved.Method != VerificationMethodPIN {
		t.Fatalf("Method = %q, want %q", resolved.Method, VerificationMethodPIN)
	}
	if !bytes.Equal(resolved.PIN, []byte("654321")) {
		t.Fatalf("PIN = %q, want 654321", string(resolved.PIN))
	}
}

func TestCredentialManagerResolveBuiltInUVAuthorization(t *testing.T) {
	manager := credentialManager{client: &client{caps: &Capabilities{RawCTAP2: &ctap2.GetInfoResponse{
		Options: map[string]bool{"uv": true, "pinUvAuthToken": true, "credMgmt": true},
	}}}}

	resolved, err := manager.resolveCredentialAuthorization(context.Background(), BuiltInUVAuthorization(), "list credentials", "Enter PIN")
	if err != nil {
		t.Fatalf("resolveCredentialAuthorization() error = %v", err)
	}
	if resolved.Method != VerificationMethodBuiltInUV {
		t.Fatalf("Method = %q, want %q", resolved.Method, VerificationMethodBuiltInUV)
	}
	if !resolved.PIN.Empty() {
		t.Fatalf("PIN is not empty for built-in UV authorization")
	}
}

func TestCredentialManagerResolveBuiltInUVRequiresAuthenticatorSupport(t *testing.T) {
	manager := credentialManager{client: &client{caps: &Capabilities{RawCTAP2: &ctap2.GetInfoResponse{
		Options: map[string]bool{"pinUvAuthToken": true, "credMgmt": true},
	}}}}

	_, err := manager.resolveCredentialAuthorization(context.Background(), BuiltInUVAuthorization(), "list credentials", "Enter PIN")
	var unavailable *VerificationMethodUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected VerificationMethodUnavailableError, got %v", err)
	}
	if unavailable.Method != VerificationMethodBuiltInUV {
		t.Fatalf("Method = %q, want %q", unavailable.Method, VerificationMethodBuiltInUV)
	}
}

func TestCredentialManagerResolveUnknownVerificationMethod(t *testing.T) {
	manager := credentialManager{client: &client{}}

	_, err := manager.resolveCredentialAuthorization(context.Background(), UVAuthorization{Method: VerificationMethod("platform")}, "list credentials", "Enter PIN")
	var unsupported *UnsupportedVerificationMethodError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected UnsupportedVerificationMethodError, got %v", err)
	}
	if unsupported.Method != VerificationMethod("platform") {
		t.Fatalf("Method = %q, want platform", unsupported.Method)
	}
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
				return handleCredentialManagementRequest(t, ctap2.CommandCredentialManagement, pinToken, rpIDHash, req[1:]), nil
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker(), WithInteraction(failingInteractionHandler{t: t}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	result, err := ctap2Candidate.Credentials().List(context.Background(), PINAuthorization(pin))
	if err != nil {
		t.Fatalf("Credentials().List() error = %v", err)
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

func TestClientListCredentialsUsesBuiltInUVAuthorization(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	uvToken := bytes.Repeat([]byte{0x33}, 32)
	rpIDHash := bytes.Repeat([]byte{0x44}, 32)

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-uv", Transport: transport.KindUSB, Product: "UV Key"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"uv": true, "pinUvAuthToken": true, "credMgmt": true},
					PinUVAuthProtocols: []uint64{1},
					Transports:         []string{"usb"},
				}), nil
			case ctap2.CommandClientPIN:
				return handleBuiltInUVClientPINRequest(t, authenticatorKey, authenticatorPublic, uvToken, req[1:]), nil
			case ctap2.CommandCredentialManagement:
				return handleCredentialManagementRequest(t, ctap2.CommandCredentialManagement, uvToken, rpIDHash, req[1:]), nil
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker(), WithInteraction(failingInteractionHandler{t: t}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	result, err := ctap2Candidate.Credentials().List(context.Background(), BuiltInUVAuthorization())
	if err != nil {
		t.Fatalf("Credentials().List() error = %v", err)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("len(Credentials) = %d, want 2", len(result.Credentials))
	}
	if got := result.Credentials[1].User.Name; got != "bob" {
		t.Fatalf("second user = %q, want bob", got)
	}
}

func TestClientListCredentialsFallsBackToCredentialManagementPreview(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	pin := "12345678"
	pinHash := sha256.Sum256([]byte(pin))
	pinToken := bytes.Repeat([]byte{0x11}, 32)
	rpIDHash := bytes.Repeat([]byte{0x22}, 32)

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindNFC, Product: "SafeNet"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions: []string{"FIDO_2_1", "FIDO_2_1_PRE"},
					AAGUID:   make([]byte, 16),
					Options: map[string]bool{
						"clientPin":                      true,
						"pinUvAuthToken":                 true,
						"credMgmt":                       true,
						"credentialMgmtPreview":          true,
						"noMcGaPermissionsWithClientPin": false,
					},
					PinUVAuthProtocols: []uint64{1},
					Transports:         []string{"nfc"},
				}), nil
			case ctap2.CommandClientPIN:
				return handleClientPINFallbackRequest(t, authenticatorKey, authenticatorPublic, pinHash[:16], pinToken, req[1:]), nil
			case ctap2.CommandCredentialManagementPreview:
				return handleCredentialManagementRequest(t, ctap2.CommandCredentialManagementPreview, pinToken, rpIDHash, req[1:]), nil
			case ctap2.CommandCredentialManagement:
				t.Fatalf("unexpected stable credential management command")
				return nil, nil
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
	result, err := ctap2Candidate.Credentials().List(context.Background(), UVAuthorization{PIN: NewSecretString(pin), Method: VerificationMethodPIN})
	if err != nil {
		t.Fatalf("Credentials().List() error = %v", err)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("len(Credentials) = %d, want 2", len(result.Credentials))
	}
	if got := result.Credentials[0].RP.ID; got != "example.com" {
		t.Fatalf("first RP = %q, want example.com", got)
	}
}

func TestClientListCredentialsRetriesTransientClientPINFailure(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	pin := "12345678"
	pinHash := sha256.Sum256([]byte(pin))
	pinToken := bytes.Repeat([]byte{0x11}, 32)
	rpIDHash := bytes.Repeat([]byte{0x22}, 32)
	permissionsAttempts := 0

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-1", Transport: transport.KindNFC, Product: "SafeNet"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions: []string{"FIDO_2_1", "FIDO_2_1_PRE"},
					AAGUID:   make([]byte, 16),
					Options: map[string]bool{
						"clientPin":                      true,
						"pinUvAuthToken":                 true,
						"credMgmt":                       true,
						"credentialMgmtPreview":          true,
						"noMcGaPermissionsWithClientPin": false,
					},
					PinUVAuthProtocols: []uint64{1},
					Transports:         []string{"nfc"},
				}), nil
			case ctap2.CommandClientPIN:
				response, usedPermissions := handleClientPINRetryRequest(t, authenticatorKey, authenticatorPublic, pinHash[:16], pinToken, req[1:])
				if usedPermissions {
					permissionsAttempts++
					if permissionsAttempts == 1 {
						return []byte{0x12}, nil
					}
				}
				return response, nil
			case ctap2.CommandCredentialManagement:
				return handleCredentialManagementRequest(t, ctap2.CommandCredentialManagement, pinToken, rpIDHash, req[1:]), nil
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
	result, err := ctap2Candidate.Credentials().List(context.Background(), UVAuthorization{PIN: NewSecretString(pin), Method: VerificationMethodPIN})
	if err != nil {
		t.Fatalf("Credentials().List() error = %v", err)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("len(Credentials) = %d, want 2", len(result.Credentials))
	}
	if permissionsAttempts != 2 {
		t.Fatalf("permissionsAttempts = %d, want 2", permissionsAttempts)
	}
}

func TestClientDeleteCredentialUsesCredentialManagement(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	pin := "123456"
	pinHash := sha256.Sum256([]byte(pin))
	pinToken := bytes.Repeat([]byte{0x11}, 32)
	deletedCredentialID := []byte{0xaa, 0xbb, 0xcc}

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
				return handleDeleteCredentialRequest(t, ctap2.CommandCredentialManagement, pinToken, deletedCredentialID, req[1:]), nil
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
	err = ctap2Candidate.Credentials().Delete(context.Background(), CredentialDescriptor{ID: deletedCredentialID}, UVAuthorization{PIN: NewSecretString(pin), Method: VerificationMethodPIN})
	if err != nil {
		t.Fatalf("Credentials().Delete() error = %v", err)
	}
}

func TestClientDeleteCredentialUsesBuiltInUVAuthorization(t *testing.T) {
	authenticatorKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	authenticatorPublic := authenticatorKey.PublicKey().Bytes()
	uvToken := bytes.Repeat([]byte{0x33}, 32)
	deletedCredentialID := []byte{0xaa, 0xbb, 0xcc}

	session := &handlerSession{
		device: transport.DeviceDescriptor{ID: "device-uv", Transport: transport.KindUSB, Product: "UV Key"},
		handler: func(ctx context.Context, req []byte) ([]byte, error) {
			switch req[0] {
			case ctap2.CommandGetInfo:
				return encodeCTAP2Success(t, ctap2.GetInfoResponse{
					Versions:           []string{"FIDO_2_1"},
					AAGUID:             make([]byte, 16),
					Options:            map[string]bool{"uv": true, "pinUvAuthToken": true, "credMgmt": true},
					PinUVAuthProtocols: []uint64{1},
					Transports:         []string{"usb"},
				}), nil
			case ctap2.CommandClientPIN:
				return handleBuiltInUVClientPINRequest(t, authenticatorKey, authenticatorPublic, uvToken, req[1:]), nil
			case ctap2.CommandCredentialManagement:
				return handleDeleteCredentialRequest(t, ctap2.CommandCredentialManagement, uvToken, deletedCredentialID, req[1:]), nil
			default:
				t.Fatalf("unexpected command 0x%02x", req[0])
				return nil, nil
			}
		},
	}

	candidate, err := New(session, WithDefaultCTAP2RawInvoker(), WithInteraction(failingInteractionHandler{t: t}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctap2Candidate, err := candidate.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	err = ctap2Candidate.Credentials().Delete(context.Background(), CredentialDescriptor{ID: deletedCredentialID}, BuiltInUVAuthorization())
	if err != nil {
		t.Fatalf("Credentials().Delete() error = %v", err)
	}
}

func handleClientPINRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, pinHash []byte, pinToken []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64           `cbor:"1,keyasint,omitempty"`
		Subcommand        uint64           `cbor:"2,keyasint"`
		KeyAgreement      *ctap2.COSEKey   `cbor:"3,keyasint,omitempty"`
		PINHashEnc        []byte           `cbor:"6,keyasint,omitempty"`
		Permissions       ctap2.Permission `cbor:"9,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN) error = %v", err)
	}

	switch request.Subcommand {
	case uint64(ctap2.ClientPINGetKeyAgreement):
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: &ctap2.COSEKey{
			KeyType:   ctap2.COSEKeyTypeEC2,
			Algorithm: ctap2.COSEAlgorithmECDHESHKDF256,
			Curve:     ctap2.COSECurveP256,
			X:         append([]byte(nil), authenticatorPublic[1:33]...),
			Y:         append([]byte(nil), authenticatorPublic[33:65]...),
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
	case uint64(ctap2.ClientPINGetPINToken):
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

func handleBuiltInUVClientPINRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, pinToken []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64           `cbor:"1,keyasint,omitempty"`
		Subcommand        uint64           `cbor:"2,keyasint"`
		KeyAgreement      *ctap2.COSEKey   `cbor:"3,keyasint,omitempty"`
		PINHashEnc        []byte           `cbor:"6,keyasint,omitempty"`
		Permissions       ctap2.Permission `cbor:"9,keyasint,omitempty"`
		PermissionsRPID   string           `cbor:"10,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN built-in UV) error = %v", err)
	}

	switch request.Subcommand {
	case uint64(ctap2.ClientPINGetKeyAgreement):
		return encodeCTAP2Success(t, ctap2.ClientPINResponse{KeyAgreement: &ctap2.COSEKey{
			KeyType:   ctap2.COSEKeyTypeEC2,
			Algorithm: ctap2.COSEAlgorithmECDHESHKDF256,
			Curve:     ctap2.COSECurveP256,
			X:         append([]byte(nil), authenticatorPublic[1:33]...),
			Y:         append([]byte(nil), authenticatorPublic[33:65]...),
		}})
	case uint64(ctap2.ClientPINGetPINTokenWithUV):
		if len(request.PINHashEnc) != 0 {
			t.Fatalf("PINHashEnc was sent for built-in UV authorization")
		}
		if request.Permissions != ctap2.PermissionCredentialManagement {
			t.Fatalf("Permissions = %d, want %d", request.Permissions, ctap2.PermissionCredentialManagement)
		}
		if request.PermissionsRPID != "" {
			t.Fatalf("PermissionsRPID = %q, want empty", request.PermissionsRPID)
		}
		platformKey, err := coseEC2PublicKey(request.KeyAgreement)
		if err != nil {
			t.Fatalf("coseEC2PublicKey() error = %v", err)
		}
		sharedPoint, err := authenticatorKey.ECDH(platformKey)
		if err != nil {
			t.Fatalf("ECDH() error = %v", err)
		}
		sharedSecret := sha256.Sum256(sharedPoint)
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

func handleClientPINFallbackRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, pinHash []byte, pinToken []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		PinUVAuthProtocol uint64           `cbor:"1,keyasint,omitempty"`
		Subcommand        uint64           `cbor:"2,keyasint"`
		KeyAgreement      *ctap2.COSEKey   `cbor:"3,keyasint,omitempty"`
		PINHashEnc        []byte           `cbor:"6,keyasint,omitempty"`
		Permissions       ctap2.Permission `cbor:"9,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN fallback) error = %v", err)
	}

	if request.Subcommand == uint64(ctap2.ClientPINGetPINTokenWithPIN) {
		return []byte{0x12}
	}
	return handleClientPINRequest(t, authenticatorKey, authenticatorPublic, pinHash, pinToken, payload)
}

func handleClientPINRetryRequest(t *testing.T, authenticatorKey *ecdh.PrivateKey, authenticatorPublic []byte, pinHash []byte, pinToken []byte, payload []byte) ([]byte, bool) {
	t.Helper()

	var request struct {
		Subcommand uint64 `cbor:"2,keyasint"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(clientPIN retry) error = %v", err)
	}
	response := handleClientPINRequest(t, authenticatorKey, authenticatorPublic, pinHash, pinToken, payload)
	return response, request.Subcommand == uint64(ctap2.ClientPINGetPINTokenWithPIN)
}

func handleCredentialManagementRequest(t *testing.T, commandCode byte, pinToken []byte, rpIDHash []byte, payload []byte) []byte {
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
		command := ctap2.NewCredentialManagementCommand(commandCode, subcommand)
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

func handleDeleteCredentialRequest(t *testing.T, commandCode byte, pinToken []byte, credentialID []byte, payload []byte) []byte {
	t.Helper()

	var request struct {
		Subcommand        uint64                                      `cbor:"1,keyasint"`
		SubcommandParams  *ctap2.CredentialManagementSubcommandParams `cbor:"2,keyasint,omitempty"`
		PinUVAuthProtocol uint64                                      `cbor:"3,keyasint,omitempty"`
		PinUVAuthParam    []byte                                      `cbor:"4,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("cbor.Unmarshal(delete credentialManagement) error = %v", err)
	}
	params := &ctap2.CredentialManagementSubcommandParams{CredentialID: &ctap2.CredentialDescriptor{Type: "public-key", ID: append([]byte(nil), credentialID...)}}
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementDeleteCredential)
	command.SubcommandParams = params
	expected, err := pinProtocol1AuthParam(pinToken, command)
	if err != nil {
		t.Fatalf("pinProtocol1AuthParam() error = %v", err)
	}
	if request.Subcommand != uint64(ctap2.CredentialManagementDeleteCredential) {
		t.Fatalf("Subcommand = %d, want %d", request.Subcommand, ctap2.CredentialManagementDeleteCredential)
	}
	if request.SubcommandParams == nil || request.SubcommandParams.CredentialID == nil {
		t.Fatalf("CredentialID params missing: %#v", request.SubcommandParams)
	}
	if got := request.SubcommandParams.CredentialID.Type; got != "public-key" {
		t.Fatalf("CredentialID.Type = %q, want public-key", got)
	}
	if !bytes.Equal(request.SubcommandParams.CredentialID.ID, credentialID) {
		t.Fatalf("CredentialID.ID = %x, want %x", request.SubcommandParams.CredentialID.ID, credentialID)
	}
	if !bytes.Equal(request.PinUVAuthParam, expected) {
		t.Fatalf("PinUVAuthParam = %x, want %x", request.PinUVAuthParam, expected)
	}
	return []byte{0x00}
}

func encodeCTAP2Success(t *testing.T, payload any) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}
	return append([]byte{0x00}, encoded...)
}
