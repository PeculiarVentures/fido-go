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

func (conn *nfcConn) Transceive(_ context.Context, request []byte) ([]byte, error) {
	conn.requests = append(conn.requests, append([]byte(nil), request...))
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

func TestBackendExchangePassesThroughAPDURequests(t *testing.T) {
	t.Parallel()

	conn := &nfcConn{responses: [][]byte{{0x11, 0x22, 0x90, 0x00}}}
	backend, err := transportnfc.NewBackend(
		&nfcDiscoverer{devices: []transport.DeviceDescriptor{{ID: "nfc-1"}}},
		&nfcOpener{conn: conn},
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

	request := []byte{0x00, 0x03, 0x00, 0x00, 0x00}
	response, err := session.Exchange(context.Background(), request)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !bytes.Equal(response, []byte{0x11, 0x22, 0x90, 0x00}) {
		t.Fatalf("response mismatch: %x", response)
	}
	if len(conn.requests) != 1 {
		t.Fatalf("len(requests) = %d, want 1", len(conn.requests))
	}
	if !bytes.Equal(conn.requests[0], request) {
		t.Fatalf("apdu request mismatch: %x", conn.requests[0])
	}
}
