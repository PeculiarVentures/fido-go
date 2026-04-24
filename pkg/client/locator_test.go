package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type locatorBackend struct {
	device transport.DeviceDescriptor
	err    error
}

func (backend *locatorBackend) Kind() transport.Kind {
	return backend.device.Transport
}

func (backend *locatorBackend) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	if backend.err != nil {
		return nil, backend.err
	}
	return []transport.DeviceDescriptor{backend.device}, nil
}

func (backend *locatorBackend) Open(context.Context, transport.DeviceDescriptor) (transport.Session, error) {
	return &locatorSession{device: backend.device}, nil
}

type locatorSession struct {
	device transport.DeviceDescriptor
}

func (session *locatorSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *locatorSession) Exchange(context.Context, []byte) ([]byte, error) {
	return nil, nil
}

func (session *locatorSession) Close() error {
	return nil
}

func TestTransportLocatorListsAndOpens(t *testing.T) {
	t.Parallel()

	locator, err := client.NewTransportLocator(&locatorBackend{device: transport.DeviceDescriptor{ID: "dev-1", Transport: transport.KindUSB}})
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}

	devices, err := locator.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 || devices[0].ID != "dev-1" {
		t.Fatal("unexpected device list")
	}

	candidate, err := locator.Open(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if candidate.Device().ID != "dev-1" {
		t.Fatal("opened wrong device")
	}
}

func TestTransportLocatorOpensWhenDiscoveryHasPartialFailures(t *testing.T) {
	t.Parallel()

	locator, err := client.NewTransportLocator(
		&locatorBackend{device: transport.DeviceDescriptor{ID: "dev-1", Transport: transport.KindUSB}},
		&locatorBackend{device: transport.DeviceDescriptor{ID: "dev-2", Transport: transport.KindNFC}, err: errors.New("pcsc unavailable")},
	)
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}

	devices, err := locator.List(context.Background())
	if err == nil {
		t.Fatal("list error = nil, want partial discovery warning")
	}
	if len(devices) != 1 || devices[0].ID != "dev-1" {
		t.Fatalf("unexpected device list: %#v", devices)
	}

	candidate, err := locator.Open(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if candidate.Device().ID != "dev-1" {
		t.Fatalf("opened wrong device: %#v", candidate.Device())
	}
}
