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

func (conn *usbConn) WritePacket(_ context.Context, packet []byte) error {
	conn.writes = append(conn.writes, append([]byte(nil), packet...))
	return nil
}

func TestBackendExplicitHIDCommandPreservesConfiguredOrdinaryCommand(t *testing.T) {
	t.Parallel()
	const channel = 0x01020304
	var reads [][]byte
	for _, command := range []byte{0xc2, 0x90} {
		codec, err := hid.NewCodec(channel, command, 16)
		if err != nil {
			t.Fatal(err)
		}
		packets, err := codec.Fragment(bytes.Repeat([]byte{command}, 20))
		if err != nil {
			t.Fatal(err)
		}
		reads = append(reads, packets...)
	}
	conn := &usbConn{reads: reads}
	backend, err := transportusb.NewBackend(&usbDiscoverer{}, &usbOpener{conn: conn}, channel, 0x90, 16)
	if err != nil {
		t.Fatal(err)
	}
	session, err := backend.Open(context.Background(), transport.DeviceDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	hidSession, ok := session.(transportusb.HIDSession)
	if !ok {
		t.Fatal("injected USB backend does not support HIDSession")
	}
	got, err := hidSession.ExchangeHID(context.Background(), 0x42, []byte{0})
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xc2}, 20)) {
		t.Fatalf("explicit exchange = %x, %v", got, err)
	}
	got, err = session.Exchange(context.Background(), []byte{4})
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x90}, 20)) {
		t.Fatalf("ordinary exchange = %x, %v", got, err)
	}
	if len(conn.writes) != 2 || conn.writes[0][4] != 0xc2 || conn.writes[0][7] != 0 || conn.writes[1][4] != 0x90 {
		t.Fatalf("packets = %x", conn.writes)
	}
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

func TestBackendOrdinaryExchangePreservesControlCommandPayloads(t *testing.T) {
	t.Parallel()
	for _, command := range []byte{0xbb, 0xbf} {
		codec, err := hid.NewCodec(0x01020304, command, 16)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{0xaa, 0xbb}
		packets, err := codec.Fragment(payload)
		if err != nil {
			t.Fatal(err)
		}
		backend, err := transportusb.NewBackend(&usbDiscoverer{}, &usbOpener{conn: &usbConn{reads: packets}}, 0x01020304, command, 16)
		if err != nil {
			t.Fatal(err)
		}
		session, err := backend.Open(context.Background(), transport.DeviceDescriptor{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := session.Exchange(context.Background(), nil)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("fixed command %02x: %x, %v", command, got, err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
