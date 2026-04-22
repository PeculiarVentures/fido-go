package ble

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wireble "github.com/PeculiarVentures/fido-go/pkg/wire/ble"
)

// PacketConn sends and receives one BLE fragment at a time.
type PacketConn interface {
	WriteFragment(ctx context.Context, fragment []byte) error
	ReadFragment(ctx context.Context) ([]byte, error)
	Close() error
}

// Discoverer lists BLE transport descriptors without opening sessions.
type Discoverer interface {
	Discover(ctx context.Context) ([]transport.DeviceDescriptor, error)
}

// Opener opens a BLE fragment connection for a descriptor.
type Opener interface {
	Open(ctx context.Context, device transport.DeviceDescriptor) (PacketConn, error)
}

// Backend discovers and opens BLE transport sessions.
type Backend struct {
	discoverer Discoverer
	opener     Opener
	mtu        int
}

// Session exchanges complete payloads over a BLE fragment connection.
type Session struct {
	device transport.DeviceDescriptor
	conn   PacketConn
	codec  *wireble.Codec
}

// NewBackend creates a BLE backend with injected discovery and connection hooks.
func NewBackend(discoverer Discoverer, opener Opener, mtu int) (*Backend, error) {
	if discoverer == nil || opener == nil {
		return nil, fmt.Errorf("transport/ble: discoverer and opener are required")
	}
	if _, err := wireble.NewCodec(mtu); err != nil {
		return nil, err
	}
	return &Backend{discoverer: discoverer, opener: opener, mtu: mtu}, nil
}

// Kind returns the BLE transport kind.
func (backend *Backend) Kind() transport.Kind {
	return transport.KindBLE
}

// Discover lists BLE descriptors and normalizes their transport kind.
func (backend *Backend) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	devices, err := backend.discoverer.Discover(ctx)
	if err != nil {
		return nil, &transport.Error{Op: "discover ble devices", Err: err}
	}
	for index := range devices {
		devices[index].Transport = transport.KindBLE
	}
	return devices, nil
}

// Open opens a BLE session for the descriptor.
func (backend *Backend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindBLE {
		return nil, &transport.Error{Op: "open ble session", Err: fmt.Errorf("transport/ble: unsupported transport %s", device.Transport)}
	}
	conn, err := backend.opener.Open(ctx, device)
	if err != nil {
		return nil, &transport.Error{Op: "open ble session", Err: err}
	}
	codec, err := wireble.NewCodec(backend.mtu)
	if err != nil {
		_ = conn.Close()
		return nil, &transport.Error{Op: "open ble session", Err: err}
	}
	device.Transport = transport.KindBLE
	return &Session{device: device, conn: conn, codec: codec}, nil
}

// Device returns the bound descriptor.
func (session *Session) Device() transport.DeviceDescriptor {
	return session.device
}

// Exchange writes a full BLE request and reassembles the full response.
func (session *Session) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	fragments, err := session.codec.Fragment(req)
	if err != nil {
		return nil, &transport.Error{Op: "fragment ble request", Err: err}
	}
	for _, fragment := range fragments {
		if err := session.conn.WriteFragment(ctx, fragment); err != nil {
			return nil, &transport.Error{Op: "write ble fragment", Err: err}
		}
	}

	assembler := session.codec.NewAssembler()
	for !assembler.Done() {
		fragment, err := session.conn.ReadFragment(ctx)
		if err != nil {
			return nil, &transport.Error{Op: "read ble fragment", Err: err}
		}
		if err := assembler.Add(fragment); err != nil {
			return nil, &transport.Error{Op: "reassemble ble response", Err: err}
		}
	}

	response, err := assembler.Payload()
	if err != nil {
		return nil, &transport.Error{Op: "reassemble ble response", Err: err}
	}
	return response, nil
}

// Close closes the underlying BLE connection.
func (session *Session) Close() error {
	if err := session.conn.Close(); err != nil {
		return &transport.Error{Op: "close ble session", Err: err}
	}
	return nil
}
