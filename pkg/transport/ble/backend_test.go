package ble_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportble "github.com/PeculiarVentures/fido-go/pkg/transport/ble"
	"github.com/PeculiarVentures/fido-go/pkg/wire/ble"
)

type bleDiscoverer struct {
	devices []transport.DeviceDescriptor
}

func (discoverer *bleDiscoverer) Discover(context.Context) ([]transport.DeviceDescriptor, error) {
	return append([]transport.DeviceDescriptor(nil), discoverer.devices...), nil
}

type bleOpener struct {
	conn transportble.PacketConn
}

func (opener *bleOpener) Open(context.Context, transport.DeviceDescriptor) (transportble.PacketConn, error) {
	return opener.conn, nil
}

type bleConn struct {
	reads [][]byte
}

func (conn *bleConn) WriteFragment(context.Context, []byte) error {
	return nil
}

func (conn *bleConn) ReadFragment(context.Context) ([]byte, error) {
	fragment := conn.reads[0]
	conn.reads = conn.reads[1:]
	return fragment, nil
}

func (conn *bleConn) Close() error {
	return nil
}

func TestBackendDiscoverAndExchange(t *testing.T) {
	t.Parallel()

	codec, err := ble.NewCodec(8)
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	responseFragments, err := codec.Fragment(bytes.Repeat([]byte{0xD1}, 15))
	if err != nil {
		t.Fatalf("fragment response: %v", err)
	}

	backend, err := transportble.NewBackend(
		&bleDiscoverer{devices: []transport.DeviceDescriptor{{ID: "ble-1"}}},
		&bleOpener{conn: &bleConn{reads: responseFragments}},
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

	response, err := session.Exchange(context.Background(), []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !bytes.Equal(response, bytes.Repeat([]byte{0xD1}, 15)) {
		t.Fatal("response mismatch")
	}
}
