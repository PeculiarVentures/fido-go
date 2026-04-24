package fidoctl

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type fakeLocator struct {
	listResponses [][]client.Device
	openClients   []client.Client
	listCalls     int
	openCalls     int
}

func (locator *fakeLocator) List(context.Context) ([]client.Device, error) {
	if locator.listCalls >= len(locator.listResponses) {
		if len(locator.listResponses) == 0 {
			return nil, nil
		}
		return locator.listResponses[len(locator.listResponses)-1], nil
	}
	response := locator.listResponses[locator.listCalls]
	locator.listCalls++
	return response, nil
}

func (locator *fakeLocator) Open(context.Context, string, ...client.Option) (client.Client, error) {
	if locator.openCalls >= len(locator.openClients) {
		return nil, &client.DeviceNotFoundError{DeviceID: ""}
	}
	opened := locator.openClients[locator.openCalls]
	locator.openCalls++
	return opened, nil
}

type fakeClient struct {
	device            transport.DeviceDescriptor
	caps              *client.DeviceCapabilities
	retries           *client.PINRetries
	pinStatus         *client.PINStatus
	credentials       *client.CredentialListResult
	lastAuthorization client.UVAuthorization
	capsErr           error
	retryErr          error
	pinStatusErr      error
	credentialsErr    error
	ctap2Err          error
	setErr            error
	changeErr         error
	resetErr          error
}

func (candidate *fakeClient) Device() transport.DeviceDescriptor {
	return candidate.device
}

func (candidate *fakeClient) Capabilities(ctx context.Context) (*client.Capabilities, error) {
	if candidate.capsErr != nil {
		return nil, candidate.capsErr
	}
	return candidate.caps, nil
}

func (candidate *fakeClient) CTAP2(context.Context) (client.CTAP2Client, error) {
	if candidate.ctap2Err != nil {
		return nil, candidate.ctap2Err
	}
	return candidate, nil
}

func (candidate *fakeClient) GetCapabilities(context.Context) (*client.DeviceCapabilities, error) {
	if candidate.capsErr != nil {
		return nil, candidate.capsErr
	}
	return candidate.caps, nil
}

func (candidate *fakeClient) GetPINRetries(context.Context) (*client.PINRetries, error) {
	if candidate.retryErr != nil {
		return nil, candidate.retryErr
	}
	return candidate.retries, nil
}

func (candidate *fakeClient) SetPIN(context.Context, string) error {
	return candidate.setErr
}

func (candidate *fakeClient) ListCredentials(context.Context, string) (*client.CredentialListResult, error) {
	return nil, nil
}

func (candidate *fakeClient) ChangePIN(context.Context, string, string) error {
	return candidate.changeErr
}

func (candidate *fakeClient) Register(context.Context, client.RegisterRequest) (*client.RegistrationResult, error) {
	return nil, nil
}

func (candidate *fakeClient) Authenticate(context.Context, client.AuthenticateRequest) (*client.AssertionResult, error) {
	return nil, nil
}

func (candidate *fakeClient) Reset(context.Context) error {
	return candidate.resetErr
}

func (candidate *fakeClient) InvokeRaw(context.Context, protocol.Family, byte, []byte) ([]byte, error) {
	return nil, nil
}

func (candidate *fakeClient) Close() error {
	return nil
}

func (candidate *fakeClient) Info(context.Context) (*client.AuthenticatorInfo, error) {
	if candidate.caps == nil {
		return nil, &client.CTAP2UnavailableError{Device: candidate.device}
	}
	if candidate.caps.RawCTAP2 != nil {
		return candidate.caps.RawCTAP2, nil
	}
	return nil, &client.CTAP2UnavailableError{Device: candidate.device}
}

func (candidate *fakeClient) PIN() client.PINManager {
	return candidate
}

func (candidate *fakeClient) Credentials() client.CredentialManager {
	return candidate
}

func (candidate *fakeClient) Bio() client.BioManager {
	return candidate
}

func (candidate *fakeClient) Status(context.Context) (*client.PINStatus, error) {
	if candidate.pinStatusErr != nil {
		return nil, candidate.pinStatusErr
	}
	if candidate.pinStatus != nil {
		return candidate.pinStatus, nil
	}
	if candidate.retryErr != nil {
		return nil, candidate.retryErr
	}
	if candidate.retries != nil {
		return &client.PINStatus{
			Configured:       true,
			Retries:          candidate.retries.PINRetries,
			UVRetries:        candidate.retries.UVRetries,
			PowerCycleNeeded: candidate.retries.PowerCycleState,
		}, nil
	}
	return &client.PINStatus{}, nil
}

func (candidate *fakeClient) Set(context.Context, string) error {
	return candidate.setErr
}

func (candidate *fakeClient) Change(context.Context, string, string) error {
	return candidate.changeErr
}

func (candidate *fakeClient) List(_ context.Context, authorization client.UVAuthorization) (*client.CredentialListResult, error) {
	candidate.lastAuthorization = authorization
	if candidate.credentialsErr != nil {
		return nil, candidate.credentialsErr
	}
	return candidate.credentials, nil
}

func (candidate *fakeClient) Delete(context.Context, ctap2.CredentialDescriptor, client.UVAuthorization) error {
	return nil
}

func (candidate *fakeClient) Supported(context.Context) (bool, error) {
	return false, nil
}

func (candidate *fakeClient) Enrollments(context.Context, client.UVAuthorization) ([]client.BioEnrollment, error) {
	return nil, nil
}

func TestInfoRetriesAfterReconnect(t *testing.T) {
	device := client.Device{ID: "device-1", Transport: transport.KindUSB, Manufacturer: "Yubico", Product: "YubiKey OTP+FIDO+CCID", VendorID: 4176, ProductID: 1031}
	locator := &fakeLocator{
		listResponses: [][]client.Device{nil, []client.Device{device}},
		openClients: []client.Client{
			&fakeClient{device: device, capsErr: &transport.Error{Op: "write usb hid packet", Err: errors.New("IOHIDDeviceSetReport failed: (0xE00002BC) (iokit/common) general error")}},
			&fakeClient{device: device, caps: &client.DeviceCapabilities{RawCTAP1: &client.CTAP1Capabilities{Version: "U2F_V2"}, RawCTAP2: &ctap2.GetInfoResponse{Versions: []string{"FIDO_2_1_PRE"}, AAGUID: make([]byte, 16)}}},
		},
	}
	app := New(locator)
	status := &bytes.Buffer{}
	app.ConfigureInteraction(true, status)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := app.Info(ctx, "")
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}
	if result.Device.ID != device.ID {
		t.Fatalf("Info() device = %q, want %q", result.Device.ID, device.ID)
	}
	if locator.openCalls != 2 {
		t.Fatalf("openCalls = %d, want 2", locator.openCalls)
	}
	if !strings.Contains(status.String(), "Authenticator connection was lost") {
		t.Fatalf("expected reconnect diagnostic, got %q", status.String())
	}
	if !strings.Contains(status.String(), "Retrying the command") {
		t.Fatalf("expected retry diagnostic, got %q", status.String())
	}
}

func TestChangePINWaitsForReconnectAfterSuccess(t *testing.T) {
	device := client.Device{ID: "device-1", Transport: transport.KindNFC, Product: "SafeNet"}
	locator := &fakeLocator{
		listResponses: [][]client.Device{nil, {device}},
		openClients:   []client.Client{&fakeClient{device: device}},
	}
	app := New(locator)
	status := &bytes.Buffer{}
	app.ConfigureInteraction(true, status)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := app.ChangePIN(ctx, "", "12345678", "87654321"); err != nil {
		t.Fatalf("ChangePIN() error = %v", err)
	}
	if locator.listCalls != 2 {
		t.Fatalf("listCalls = %d, want 2", locator.listCalls)
	}
	if !strings.Contains(status.String(), "Waiting for authenticator to reconnect after PIN change") {
		t.Fatalf("expected reconnect wait diagnostic, got %q", status.String())
	}
	if !strings.Contains(status.String(), "Authenticator detected again") {
		t.Fatalf("expected reconnect success diagnostic, got %q", status.String())
	}
}

func TestSetPINWaitsForReconnectAfterSuccess(t *testing.T) {
	device := client.Device{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}
	locator := &fakeLocator{
		listResponses: [][]client.Device{nil, {device}},
		openClients:   []client.Client{&fakeClient{device: device}},
	}
	app := New(locator)
	status := &bytes.Buffer{}
	app.ConfigureInteraction(true, status)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := app.SetPIN(ctx, "", "12345678"); err != nil {
		t.Fatalf("SetPIN() error = %v", err)
	}
	if locator.listCalls != 2 {
		t.Fatalf("listCalls = %d, want 2", locator.listCalls)
	}
	if !strings.Contains(status.String(), "Waiting for authenticator to reconnect after PIN setup") {
		t.Fatalf("expected reconnect wait diagnostic, got %q", status.String())
	}
	if !strings.Contains(status.String(), "Authenticator detected again") {
		t.Fatalf("expected reconnect success diagnostic, got %q", status.String())
	}
}

func TestPINRetriesReadsRetryCounters(t *testing.T) {
	device := client.Device{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}
	locator := &fakeLocator{
		openClients: []client.Client{&fakeClient{
			device:  device,
			retries: &client.PINRetries{PINRetries: 8, UVRetries: 5},
		}},
	}
	app := New(locator)

	result, err := app.PINRetries(context.Background(), "")
	if err != nil {
		t.Fatalf("PINRetries() error = %v", err)
	}
	if result.Device.ID != device.ID {
		t.Fatalf("device ID = %q, want %q", result.Device.ID, device.ID)
	}
	if result.PINRetries.PINRetries != 8 {
		t.Fatalf("PINRetries = %d, want 8", result.PINRetries.PINRetries)
	}
	if result.PINRetries.UVRetries != 5 {
		t.Fatalf("UVRetries = %d, want 5", result.PINRetries.UVRetries)
	}
}

func TestOnInteractionWritesStatus(t *testing.T) {
	app := New(&fakeLocator{})
	status := &bytes.Buffer{}
	app.ConfigureInteraction(true, status)

	app.OnInteraction(context.Background(), client.InteractionEvent{
		Kind:    client.InteractionAwaitingUserPresence,
		Message: "Touch the authenticator to continue.",
	})

	if !strings.Contains(status.String(), "Touch the authenticator to continue.") {
		t.Fatalf("expected interaction status, got %q", status.String())
	}
}
