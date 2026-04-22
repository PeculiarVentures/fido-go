package usb_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportusb "github.com/PeculiarVentures/fido-go/pkg/transport/usb"
	"github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

type usbDiscoverer struct {
	devices []transport.DeviceDescriptor
}

func (discoverer *usbDiscoverer) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	return append([]transport.DeviceDescriptor(nil), discoverer.devices...), nil
}

type usbOpener struct {
	conn transportusb.PacketConn
}

func (opener *usbOpener) Open(context.Context, transport.DeviceDescriptor) (transportusb.PacketConn, error) {
	return opener.conn, nil
}

type usbConn struct {
	reads  [][]byte
	writes [][]byte
}

func (conn *usbConn) WritePacket(context.Context, []byte) error {
	return nil
}

func (conn *usbConn) ReadPacket(context.Context) ([]byte, error) {
	packet := conn.reads[0]
	conn.reads = conn.reads[1:]
	return packet, nil
}

func (conn *usbConn) Close() error {
	return nil
}

func TestBackendDiscoverAndExchange(t *testing.T) {
	t.Parallel()

	codec, err := hid.NewCodec(0x01020304, 0x90, 16)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	responsePackets, err := codec.Fragment(bytes.Repeat([]byte{0xEF}, 20))
	if err != nil {
		t.Fatalf("fragment response: %v", err)
	}

	backend, err := transportusb.NewBackend(
		&usbDiscoverer{devices: []transport.DeviceDescriptor{{ID: "usb-1"}}},
		&usbOpener{conn: &usbConn{reads: responsePackets}},
		0x01020304,
		0x90,
		16,
	)
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}

	devices, err := backend.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	session, err := backend.Open(context.Background(), devices[0])
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	response, err := session.Exchange(context.Background(), []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !bytes.Equal(response, bytes.Repeat([]byte{0xEF}, 20)) {
		t.Fatal("response mismatch")
	}
}
