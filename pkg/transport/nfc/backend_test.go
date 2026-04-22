package nfc_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportnfc "github.com/PeculiarVentures/fido-go/pkg/transport/nfc"
)

type nfcDiscoverer struct {
	devices []transport.DeviceDescriptor
}

func (discoverer *nfcDiscoverer) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	return append([]transport.DeviceDescriptor(nil), discoverer.devices...), nil
}

type nfcOpener struct {
	conn transportnfc.Transceiver
}

func (opener *nfcOpener) Open(context.Context, transport.DeviceDescriptor) (transportnfc.Transceiver, error) {
	return opener.conn, nil
}

type nfcConn struct {
	responses [][]byte
	requests  [][]byte
}

func (conn *nfcConn) Transceive(context.Context, []byte) ([]byte, error) {
	response := conn.responses[0]
	conn.responses = conn.responses[1:]
	return response, nil
}

func (conn *nfcConn) Close() error {
	return nil
}

func TestBackendDiscoverAndExchange(t *testing.T) {
	t.Parallel()

	backend, err := transportnfc.NewBackend(
		&nfcDiscoverer{devices: []transport.DeviceDescriptor{{ID: "nfc-1"}}},
		&nfcOpener{conn: &nfcConn{responses: [][]byte{{0x90, 0x00}, {0xAA, 0x61, 0x01}, {0xBB, 0x90, 0x00}}}},
		0x80,
		0x10,
		0x00,
		0x00,
		8,
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

	response, err := session.Exchange(context.Background(), bytes.Repeat([]byte{0x33}, 12))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !bytes.Equal(response, []byte{0xAA, 0xBB}) {
		t.Fatal("response mismatch")
	}
}
