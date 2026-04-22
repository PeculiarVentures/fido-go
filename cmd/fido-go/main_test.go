package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type fakeLocator struct {
	devices []client.Device
	client  client.Client
}

func (locator *fakeLocator) List(context.Context) ([]client.Device, error) {
	return append([]client.Device(nil), locator.devices...), nil
}

func (locator *fakeLocator) Open(context.Context, string, ...client.Option) (client.Client, error) {
	return locator.client, nil
}

type fakeClient struct {
	device       client.Device
	capabilities *client.DeviceCapabilities
	rawResponse  []byte
	register     *client.RegistrationResult
	assertion    *client.AssertionResult
}

func (candidate *fakeClient) Device() transport.DeviceDescriptor {
	return candidate.device
}

func (candidate *fakeClient) GetCapabilities(context.Context) (*client.DeviceCapabilities, error) {
	return candidate.capabilities, nil
}

func (candidate *fakeClient) Register(context.Context, client.RegisterRequest) (*client.RegistrationResult, error) {
	return candidate.register, nil
}

func (candidate *fakeClient) Authenticate(context.Context, client.AuthenticateRequest) (*client.AssertionResult, error) {
	return candidate.assertion, nil
}

func (candidate *fakeClient) Reset(context.Context) error {
	return nil
}

func (candidate *fakeClient) InvokeRaw(context.Context, client.ProtocolFamily, byte, []byte) ([]byte, error) {
	return append([]byte(nil), candidate.rawResponse...), nil
}

func (candidate *fakeClient) Close() error {
	return nil
}

func TestRunListJSON(t *testing.T) {
	t.Parallel()

	app := &application{locator: &fakeLocator{devices: []client.Device{{ID: "dev-1", Transport: transport.KindUSB, Product: "Key"}}}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.run(context.Background(), []string{"list", "--format", "json"}, &stdout, &stderr)
	if exitCode != exitSuccess {
		t.Fatalf("unexpected exit code: %d, stderr=%s", exitCode, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("dev-1")) {
		t.Fatal("expected device id in output")
	}
}

func TestRunRawHuman(t *testing.T) {
	t.Parallel()

	app := &application{locator: &fakeLocator{client: &fakeClient{device: client.Device{ID: "dev-1"}, rawResponse: []byte{0xAA}}}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.run(context.Background(), []string{"raw", "--device-id", "dev-1", "--command", "4", "--payload", "", "--protocol", "ctap2"}, &stdout, &stderr)
	if exitCode != exitSuccess {
		t.Fatalf("unexpected exit code: %d, stderr=%s", exitCode, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("aa")) {
		t.Fatal("expected raw response in output")
	}
}
