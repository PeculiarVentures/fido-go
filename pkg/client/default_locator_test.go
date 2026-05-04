package client

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

func TestNewDefaultLocatorUsesUSBOnlyByDefault(t *testing.T) {
	usbBackend := &defaultLocatorBackend{kind: transport.KindUSB, devices: []transport.DeviceDescriptor{{ID: "usb-1", Transport: transport.KindUSB}}}
	nfcCalled := false

	previousUSB := newDefaultUSBBackend
	previousNFC := newDefaultNFCBackend
	t.Cleanup(func() {
		newDefaultUSBBackend = previousUSB
		newDefaultNFCBackend = previousNFC
	})

	newDefaultUSBBackend = func() transport.Backend { return usbBackend }
	newDefaultNFCBackend = func() (transport.Backend, error) {
		nfcCalled = true
		return &defaultLocatorBackend{kind: transport.KindNFC, devices: []transport.DeviceDescriptor{{ID: "nfc-1", Transport: transport.KindNFC}}}, nil
	}

	locator, err := NewDefaultLocator()
	if err != nil {
		t.Fatalf("NewDefaultLocator() error = %v", err)
	}
	if nfcCalled {
		t.Fatal("NewDefaultLocator() unexpectedly initialized the NFC backend by default")
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

func TestNewDefaultLocatorWithNFCAddsNFCBackend(t *testing.T) {
	usbBackend := &defaultLocatorBackend{kind: transport.KindUSB, devices: []transport.DeviceDescriptor{{ID: "usb-1", Transport: transport.KindUSB}}}
	nfcBackend := &defaultLocatorBackend{kind: transport.KindNFC, devices: []transport.DeviceDescriptor{{ID: "nfc-1", Transport: transport.KindNFC}}}

	previousUSB := newDefaultUSBBackend
	previousNFC := newDefaultNFCBackend
	t.Cleanup(func() {
		newDefaultUSBBackend = previousUSB
		newDefaultNFCBackend = previousNFC
	})

	newDefaultUSBBackend = func() transport.Backend { return usbBackend }
	newDefaultNFCBackend = func() (transport.Backend, error) {
		return nfcBackend, nil
	}

	locator, err := NewDefaultLocator(WithNFC(true))
	if err != nil {
		t.Fatalf("NewDefaultLocator(WithNFC(true)) error = %v", err)
	}

	devices, err := locator.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
	if devices[0].Transport != transport.KindUSB {
		t.Fatalf("devices[0].transport = %q, want %q", devices[0].Transport, transport.KindUSB)
	}
	if devices[1].Transport != transport.KindNFC {
		t.Fatalf("devices[1].transport = %q, want %q", devices[1].Transport, transport.KindNFC)
	}
}

func TestNewDefaultLocatorWithNFCReturnsBackendError(t *testing.T) {
	expected := errors.New("pcsc unavailable")

	previousUSB := newDefaultUSBBackend
	previousNFC := newDefaultNFCBackend
	t.Cleanup(func() {
		newDefaultUSBBackend = previousUSB
		newDefaultNFCBackend = previousNFC
	})

	newDefaultUSBBackend = func() transport.Backend {
		return &defaultLocatorBackend{kind: transport.KindUSB, devices: []transport.DeviceDescriptor{{ID: "usb-1", Transport: transport.KindUSB}}}
	}
	newDefaultNFCBackend = func() (transport.Backend, error) {
		return nil, expected
	}

	_, err := NewDefaultLocator(WithNFC(true))
	if !errors.Is(err, expected) {
		t.Fatalf("NewDefaultLocator(WithNFC(true)) error = %v, want %v", err, expected)
	}
}

func TestNewDefaultLocatorRequiresAtLeastOneTransport(t *testing.T) {
	_, err := NewDefaultLocator(WithUSB(false))
	if !errors.Is(err, errDefaultLocatorTransportRequired) {
		t.Fatalf("NewDefaultLocator(WithUSB(false)) error = %v, want %v", err, errDefaultLocatorTransportRequired)
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
