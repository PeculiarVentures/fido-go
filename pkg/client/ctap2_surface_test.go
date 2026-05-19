package client_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/fxamacker/cbor/v2"
)

func TestClientCapabilitiesNormalizesCTAP2State(t *testing.T) {
	t.Parallel()

	getInfoPayload, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_1", "U2F_V2"},
		3: bytes.Repeat([]byte{0xAB}, 16),
		4: map[string]bool{
			"clientPin":             false,
			"uv":                    true,
			"pinUvAuthToken":        true,
			"credMgmt":              true,
			"bioEnroll":             false,
			"rk":                    true,
			"credentialMgmtPreview": false,
		},
		6: []uint64{1},
	})
	if err != nil {
		t.Fatalf("marshal get info payload: %v", err)
	}

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-ctap2", Transport: transport.KindNFC},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			switch {
			case bytes.Equal(req, []byte{ctap2.CommandGetInfo}):
				return append([]byte{0x00}, getInfoPayload...), nil
			case bytes.Equal(req, []byte{0x00, 0x03, 0x00, 0x00, 0x00}):
				return []byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0x00}, nil
			default:
				return nil, errors.New("unexpected request")
			}
		},
	}

	sdk, err := client.New(session, client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	caps, err := sdk.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if !caps.Protocols.CTAP2 || !caps.Protocols.CTAP1 {
		t.Fatalf("unexpected protocol capabilities: %#v", caps.Protocols)
	}
	if caps.Protocols.Preferred != client.FamilyCTAP2 {
		t.Fatalf("preferred protocol = %q, want ctap2", caps.Protocols.Preferred)
	}
	if !caps.Authenticator.ResidentKey || !caps.Authenticator.CredentialManagement {
		t.Fatalf("unexpected authenticator capabilities: %#v", caps.Authenticator)
	}
	if !caps.Verification.ClientPIN || !caps.Verification.BuiltInUV || !caps.Verification.PinUVAuthToken || !caps.Verification.BioEnrollment {
		t.Fatalf("unexpected verification capabilities: %#v", caps.Verification)
	}
	if !caps.Interaction.UserPresence || !caps.Interaction.UserVerification || !caps.Interaction.BuiltInUV || !caps.Interaction.NFCImplicitPresence {
		t.Fatalf("unexpected interaction capabilities: %#v", caps.Interaction)
	}

	cachedCopy, err := sdk.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("second Capabilities() error = %v", err)
	}
	if cachedCopy == caps {
		t.Fatal("expected Capabilities() to return a defensive copy")
	}
	if cachedCopy.RawCTAP2 == caps.RawCTAP2 {
		t.Fatal("expected RawCTAP2 to be cloned")
	}
	caps.RawCTAP2.Options["pinUvAuthToken"] = false
	thirdCopy, err := sdk.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("third Capabilities() error = %v", err)
	}
	if !thirdCopy.RawCTAP2.Options["pinUvAuthToken"] {
		t.Fatal("mutating returned capabilities changed cached canonical capabilities")
	}
}

func TestUVAuthorizationConstructors(t *testing.T) {
	t.Parallel()

	defaultAuthorization := client.DefaultUVAuthorization()
	if defaultAuthorization.Method != "" || !defaultAuthorization.PIN.Empty() {
		t.Fatalf("DefaultUVAuthorization() = %#v, want empty authorization", defaultAuthorization)
	}

	pinAuthorization := client.PINAuthorization("123456")
	if pinAuthorization.Method != client.VerificationMethodPIN {
		t.Fatalf("PINAuthorization().Method = %q, want %q", pinAuthorization.Method, client.VerificationMethodPIN)
	}
	if !bytes.Equal(pinAuthorization.PIN, []byte("123456")) {
		t.Fatalf("PINAuthorization().PIN = %q, want 123456", string(pinAuthorization.PIN))
	}

	secret := client.NewSecretString("654321")
	secretAuthorization := client.SecretPINAuthorization(secret)
	if secretAuthorization.Method != client.VerificationMethodPIN {
		t.Fatalf("SecretPINAuthorization().Method = %q, want %q", secretAuthorization.Method, client.VerificationMethodPIN)
	}
	if !bytes.Equal(secretAuthorization.PIN, secret) {
		t.Fatalf("SecretPINAuthorization().PIN = %q, want supplied secret", string(secretAuthorization.PIN))
	}

	builtInUVAuthorization := client.BuiltInUVAuthorization()
	if builtInUVAuthorization.Method != client.VerificationMethodBuiltInUV {
		t.Fatalf("BuiltInUVAuthorization().Method = %q, want %q", builtInUVAuthorization.Method, client.VerificationMethodBuiltInUV)
	}
	if !builtInUVAuthorization.PIN.Empty() {
		t.Fatalf("BuiltInUVAuthorization().PIN is not empty")
	}
}

func TestClientCTAP2SurfaceReturnsInfoAndPINStatus(t *testing.T) {
	t.Parallel()

	getInfoPayload, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_1"},
		3: bytes.Repeat([]byte{0xCD}, 16),
		4: map[string]bool{"clientPin": false},
		6: []uint64{1},
	})
	if err != nil {
		t.Fatalf("marshal get info payload: %v", err)
	}

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-pin", Transport: transport.KindUSB},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			if !bytes.Equal(req, []byte{ctap2.CommandGetInfo}) {
				return nil, errors.New("unexpected request")
			}
			return append([]byte{0x00}, getInfoPayload...), nil
		},
	}

	sdk, err := client.New(session, client.WithRawInvoker(testCTAP2Invoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	surface, err := sdk.CTAP2(context.Background())
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	info, err := surface.Info(context.Background())
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	if len(info.Versions) != 1 || info.Versions[0] != "FIDO_2_1" {
		t.Fatalf("unexpected info versions: %#v", info.Versions)
	}
	status, err := surface.PIN().Status(context.Background())
	if err != nil {
		t.Fatalf("PIN().Status() error = %v", err)
	}
	if status.Configured {
		t.Fatal("expected PIN to be reported as not configured")
	}
	if status.Retries != 0 || status.UVRetries != 0 || status.PowerCycleNeeded {
		t.Fatalf("unexpected PIN status: %#v", status)
	}
}

func TestClientCTAP2ReturnsTypedErrorForCTAP1OnlyDevice(t *testing.T) {
	t.Parallel()

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-u2f", Transport: transport.KindUSB},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			if !bytes.Equal(req, []byte{0x00, 0x03, 0x00, 0x00, 0x00}) {
				return nil, errors.New("unexpected request")
			}
			return []byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0x00}, nil
		},
	}

	sdk, err := client.New(session, client.WithRawInvoker(testCTAP1Invoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = sdk.CTAP2(context.Background())
	var unavailable *client.CTAP2UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected CTAP2UnavailableError, got %v", err)
	}
}

type testCTAP2Invoker struct{}

func (testCTAP2Invoker) Protocol() client.ProtocolFamily {
	return client.FamilyCTAP2
}

func (testCTAP2Invoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	request := append([]byte{command}, payload...)
	return exchange(ctx, request)
}

type testCTAP1Invoker struct{}

func (testCTAP1Invoker) Protocol() client.ProtocolFamily {
	return client.FamilyCTAP1
}

func (testCTAP1Invoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	var (
		request []byte
		err     error
	)
	if command == ctap1.CommandVersion && len(payload) == 0 {
		request, err = ctap1.EncodeShortAPDU(command, nil)
	} else {
		request, err = ctap1.EncodeRawAPDU(command, payload)
	}
	if err != nil {
		return nil, err
	}
	return exchange(ctx, request)
}
