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
	device    transport.DeviceDescriptor
	caps      *client.DeviceCapabilities
	capsErr   error
	changeErr error
}

func (candidate *fakeClient) Device() transport.DeviceDescriptor {
	return candidate.device
}

func (candidate *fakeClient) GetCapabilities(context.Context) (*client.DeviceCapabilities, error) {
	if candidate.capsErr != nil {
		return nil, candidate.capsErr
	}
	return candidate.caps, nil
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
	return nil
}

func (candidate *fakeClient) InvokeRaw(context.Context, protocol.Family, byte, []byte) ([]byte, error) {
	return nil, nil
}

func (candidate *fakeClient) Close() error {
	return nil
}

func TestInfoRetriesAfterReconnect(t *testing.T) {
	device := client.Device{ID: "device-1", Transport: transport.KindUSB, Manufacturer: "Yubico", Product: "YubiKey OTP+FIDO+CCID", VendorID: 4176, ProductID: 1031}
	locator := &fakeLocator{
		listResponses: [][]client.Device{nil, []client.Device{device}},
		openClients: []client.Client{
			&fakeClient{device: device, capsErr: &transport.Error{Op: "write usb hid packet", Err: errors.New("IOHIDDeviceSetReport failed: (0xE00002BC) (iokit/common) general error")}},
			&fakeClient{device: device, caps: &client.DeviceCapabilities{CTAP1: &client.CTAP1Capabilities{Version: "U2F_V2"}, CTAP2: &ctap2.GetInfoResponse{Versions: []string{"FIDO_2_1_PRE"}, AAGUID: make([]byte, 16)}}},
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
