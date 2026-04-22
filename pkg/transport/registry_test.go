package transport_test

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type testBackend struct {
	kind    transport.Kind
	devices []transport.DeviceDescriptor
}

func (backend *testBackend) Kind() transport.Kind {
	return backend.kind
}

func (backend *testBackend) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	return append([]transport.DeviceDescriptor(nil), backend.devices...), nil
}

func (backend *testBackend) Open(context.Context, transport.DeviceDescriptor) (transport.Session, error) {
	return &testSession{device: backend.devices[0]}, nil
}

type testSession struct {
	device transport.DeviceDescriptor
}

func (session *testSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *testSession) Exchange(context.Context, []byte) ([]byte, error) {
	return nil, nil
}

func (session *testSession) Close() error {
	return nil
}

func TestRegistryDiscoverAndOpen(t *testing.T) {
	t.Parallel()

	registry, err := transport.NewRegistry(
		&testBackend{kind: transport.KindUSB, devices: []transport.DeviceDescriptor{{ID: "usb-1", Transport: transport.KindUSB}}},
		&testBackend{kind: transport.KindNFC, devices: []transport.DeviceDescriptor{{ID: "nfc-1", Transport: transport.KindNFC}}},
	)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	devices, err := registry.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("unexpected device count: %d", len(devices))
	}

	session, err := registry.Open(context.Background(), devices[0])
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if session.Device().Transport != devices[0].Transport {
		t.Fatal("opened session for wrong transport")
	}
}
