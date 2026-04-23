package client

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

func TestNewDefaultLocatorFallsBackToUSBWhenNFCUnavailable(t *testing.T) {
	t.Parallel()

	usbBackend := &defaultLocatorBackend{kind: transport.KindUSB, devices: []transport.DeviceDescriptor{{ID: "usb-1", Transport: transport.KindUSB}}}

	previousUSB := newDefaultUSBBackend
	previousNFC := newDefaultNFCBackend
	t.Cleanup(func() {
		newDefaultUSBBackend = previousUSB
		newDefaultNFCBackend = previousNFC
	})

	newDefaultUSBBackend = func() transport.Backend { return usbBackend }
	newDefaultNFCBackend = func() (transport.Backend, error) {
		return nil, errors.New("pcsc unavailable")
	}

	locator, err := NewDefaultLocator()
	if err != nil {
		t.Fatalf("NewDefaultLocator() error = %v", err)
	}

	devices, err := locator.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].ID != "usb-1" {
		t.Fatalf("device ID = %q, want usb-1", devices[0].ID)
	}
}

type defaultLocatorBackend struct {
	kind    transport.Kind
	devices []transport.DeviceDescriptor
}

func (backend *defaultLocatorBackend) Kind() transport.Kind {
	return backend.kind
}

func (backend *defaultLocatorBackend) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	return append([]transport.DeviceDescriptor(nil), backend.devices...), nil
}

func (backend *defaultLocatorBackend) Open(context.Context, transport.DeviceDescriptor) (transport.Session, error) {
	return &defaultLocatorSession{device: backend.devices[0]}, nil
}

type defaultLocatorSession struct {
	device transport.DeviceDescriptor
}

func (session *defaultLocatorSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *defaultLocatorSession) Exchange(context.Context, []byte) ([]byte, error) {
	return nil, nil
}

func (session *defaultLocatorSession) Close() error {
	return nil
}
