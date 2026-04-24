//go:build integration

package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/fxamacker/cbor/v2"
)

func TestCredentialLifecycleOnAuthenticator(t *testing.T) {
	deviceID := os.Getenv("FIDO_TEST_DEVICE_ID")
	pin := os.Getenv("FIDO_TEST_PIN")
	if deviceID == "" || pin == "" {
		t.Skip("set FIDO_TEST_DEVICE_ID and FIDO_TEST_PIN to run integration credential lifecycle test")
	}

	rpID := os.Getenv("FIDO_TEST_RPID")
	if rpID == "" {
		rpID = fmt.Sprintf("fido-go-%d.example", time.Now().UnixNano())
	}
	userName := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	challengeHash := randomBytes(t, 32)
	userID := randomBytes(t, 16)
	authorization := client.UVAuthorization{PIN: client.NewSecretString(pin), Method: client.VerificationMethodPIN}
	interaction := staticPINInteractionHandler{t: t, pin: pin}
	recorder := client.NewTraceRecorder()

	locator, err := client.NewDefaultLocator()
	if err != nil {
		t.Fatalf("NewDefaultLocator() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sdk, err := locator.Open(ctx, deviceID, client.WithDefaultRawInvokers(), client.WithInteraction(interaction), client.WithTrace(recorder))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := sdk.Close(); err != nil {
			t.Logf("Close() error = %v", err)
		}
	}()

	ctap2Client, err := sdk.CTAP2(ctx)
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	info, err := ctap2Client.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	t.Logf("device=%s versions=%v options=%v transports=%v", deviceID, info.Versions, info.Options, info.Transports)
	if !info.Options["rk"] {
		t.Fatalf("authenticator does not report resident key support: options=%v", info.Options)
	}
	if !info.Options["credMgmt"] && !info.Options["credentialMgmtPreview"] {
		t.Fatalf("authenticator does not report credential management support: options=%v", info.Options)
	}
	if !info.Options["clientPin"] {
		t.Fatalf("authenticator does not report clientPin support: options=%v", info.Options)
	}

	registerResult, err := sdk.Register(ctx, client.RegistrationRequest{
		ChallengeHash: challengeHash,
		RPID:          rpID,
		User: client.User{
			ID:          userID,
			Name:        userName,
			DisplayName: userName,
		},
		Selection: client.AuthenticatorSelection{
			UserVerification: client.UserVerificationRequired,
		},
		CTAP2: &client.CTAP2RegistrationOptions{
			RPName:      "fido-go integration",
			ResidentKey: true,
		},
	})
	if err != nil {
		logTraceEvents(t, recorder)
		t.Fatalf("Register() error = %v", err)
	}
	if registerResult.Protocol != client.FamilyCTAP2 {
		t.Fatalf("Register() protocol = %q, want %q", registerResult.Protocol, client.FamilyCTAP2)
	}
	t.Logf("created credential id=%x rpId=%s", registerResult.CredentialID, rpID)

	createdCredential, credentials, err := findCredential(ctx, ctap2Client, authorization, registerResult.CredentialID)
	if err != nil {
		t.Fatalf("findCredential(after create) error = %v", err)
	}
	if createdCredential == nil {
		t.Fatalf("created credential %x not found after registration; listed=%d", registerResult.CredentialID, len(credentials))
	}
	defer func() {
		if createdCredential == nil {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := ctap2Client.Credentials().Delete(cleanupCtx, createdCredential.Credential, authorization); err != nil {
			t.Logf("cleanup delete failed for %x: %v", createdCredential.Credential.ID, err)
		}
	}()

	if createdCredential.RP.ID == "" {
		t.Fatalf("created credential returned an empty RP id for %x", registerResult.CredentialID)
	}
	if len(createdCredential.User.ID) == 0 {
		t.Fatalf("created credential returned an empty user id for %x", registerResult.CredentialID)
	}

	if err := ctap2Client.Credentials().Delete(ctx, createdCredential.Credential, authorization); err != nil {
		logTraceEvents(t, recorder)
		t.Fatalf("Credentials().Delete() error = %v", err)
	}
	createdCredential = nil

	deletedCredential, remaining, err := findCredential(ctx, ctap2Client, authorization, registerResult.CredentialID)
	if err != nil {
		t.Fatalf("findCredential(after delete) error = %v", err)
	}
	if deletedCredential != nil {
		t.Fatalf("credential %x still present after delete; listed=%d", registerResult.CredentialID, len(remaining))
	}
	t.Logf("deleted credential id=%x", registerResult.CredentialID)
}

func TestCredentialManagementUsesPINUVAuthProtocol2OnAuthenticator(t *testing.T) {
	if os.Getenv("FIDO_TEST_PIN_UV_PROTOCOL2") == "" {
		t.Skip("set FIDO_TEST_PIN_UV_PROTOCOL2=1 to run pinUvAuthProtocol 2 integration test")
	}

	deviceID := os.Getenv("FIDO_TEST_DEVICE_ID")
	pin := os.Getenv("FIDO_TEST_PIN")
	if deviceID == "" || pin == "" {
		t.Skip("set FIDO_TEST_DEVICE_ID and FIDO_TEST_PIN to run pinUvAuthProtocol 2 integration test")
	}

	authorization := client.UVAuthorization{PIN: client.NewSecret([]byte(pin)), Method: client.VerificationMethodPIN}
	recorder := client.NewTraceRecorder()
	interaction := staticPINInteractionHandler{t: t, pin: pin}

	locator, err := client.NewDefaultLocator()
	if err != nil {
		t.Fatalf("NewDefaultLocator() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sdk, err := locator.Open(
		ctx,
		deviceID,
		client.WithDefaultRawInvokers(),
		client.WithInteraction(interaction),
		client.WithTrace(recorder, client.TraceOptions{RedactSecrets: false}),
	)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if err := sdk.Close(); err != nil {
			t.Logf("Close() error = %v", err)
		}
	}()

	ctap2Client, err := sdk.CTAP2(ctx)
	if err != nil {
		t.Fatalf("CTAP2() error = %v", err)
	}
	info, err := ctap2Client.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	if !containsPINUVAuthProtocol(info.PinUVAuthProtocols, 2) {
		t.Fatalf("authenticator does not advertise pinUvAuthProtocol 2: %v", info.PinUVAuthProtocols)
	}
	if !info.Options["clientPin"] {
		t.Fatalf("authenticator does not report clientPin support: options=%v", info.Options)
	}
	if !info.Options["credMgmt"] && !info.Options["credentialMgmtPreview"] {
		t.Fatalf("authenticator does not report credential management support: options=%v", info.Options)
	}

	if _, err := ctap2Client.Credentials().List(ctx, authorization); err != nil {
		logTraceEvents(t, recorder)
		t.Fatalf("Credentials().List() error = %v", err)
	}

	usedProtocol2, err := traceContainsClientPINProtocol(recorder.Events(), 2)
	if err != nil {
		logTraceEvents(t, recorder)
		t.Fatalf("traceContainsClientPINProtocol() error = %v", err)
	}
	if !usedProtocol2 {
		logTraceEvents(t, recorder)
		t.Fatalf("trace did not contain a ClientPIN request using pinUvAuthProtocol 2")
	}
	logTraceEvents(t, recorder)
}

type staticPINInteractionHandler struct {
	t   *testing.T
	pin string
}

func (handler staticPINInteractionHandler) OnInteraction(_ context.Context, event client.InteractionEvent) {
	handler.t.Logf("interaction kind=%s operation=%s transport=%s message=%s", event.Kind, event.Operation, event.Transport, event.Message)
}

func (handler staticPINInteractionHandler) RequestPIN(_ context.Context, req client.PINRequest) (client.Secret, error) {
	handler.t.Logf("pin request operation=%s transport=%s message=%s", req.Operation, req.Transport, req.Message)
	return client.NewSecretString(handler.pin), nil
}

func findCredential(ctx context.Context, ctap2Client client.CTAP2Client, authorization client.UVAuthorization, credentialID []byte) (*client.DiscoverableCredential, []client.DiscoverableCredential, error) {
	list, err := ctap2Client.Credentials().List(ctx, authorization)
	if err != nil {
		return nil, nil, err
	}
	for idx := range list.Credentials {
		credential := &list.Credentials[idx]
		if bytes.Equal(credential.Credential.ID, credentialID) {
			return credential, list.Credentials, nil
		}
	}
	return nil, list.Credentials, nil
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return buffer
}

func logTraceEvents(t *testing.T, recorder *client.TraceRecorder) {
	t.Helper()
	for index, event := range recorder.Events() {
		t.Logf("trace[%d] direction=%s len=%d payload=%x", index, event.Direction, len(event.Payload), event.Payload)
	}
}

func containsPINUVAuthProtocol(protocols []uint64, target uint64) bool {
	for _, protocolVersion := range protocols {
		if protocolVersion == target {
			return true
		}
	}
	return false
}

func traceContainsClientPINProtocol(events []client.TraceEvent, protocolVersion uint64) (bool, error) {
	for _, event := range events {
		if event.Direction != client.TraceDirectionRequest || event.Command != 0x06 || len(event.Payload) <= 1 {
			continue
		}
		var request struct {
			PinUVAuthProtocol uint64 `cbor:"1,keyasint,omitempty"`
		}
		if err := cbor.Unmarshal(event.Payload[1:], &request); err != nil {
			return false, fmt.Errorf("decode clientPIN trace payload: %w", err)
		}
		if request.PinUVAuthProtocol == protocolVersion {
			return true, nil
		}
	}
	return false, nil
}

var _ client.InteractionHandler = staticPINInteractionHandler{}
