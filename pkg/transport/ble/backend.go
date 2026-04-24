package ble

import (
	"context"
	"fmt"
	"sync"

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
	mu     sync.Mutex
	device transport.DeviceDescriptor
	conn   PacketConn
	codec  *wireble.Codec
}

// NewBackend creates a BLE backend with injected discovery and connection hooks.
//
// The package currently provides a testable/custom transport foundation only.
// A production BLE backend can be added later without changing the session API.
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
	for index := range devices {
		devices[index].Transport = transport.KindBLE
	}
	if err != nil {
		return devices, transport.Wrap("discover ble devices", transport.ClassifyCommon(err))
	}
	return devices, nil
}

// Open opens a BLE session for the descriptor.
func (backend *Backend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindBLE {
		return nil, transport.Wrap("open ble session", transport.Unsupported(fmt.Errorf("transport/ble: unsupported transport %s", device.Transport)))
	}
	conn, err := backend.opener.Open(ctx, device)
	if err != nil {
		return nil, transport.Wrap("open ble session", transport.ClassifyCommon(err))
	}
	codec, err := wireble.NewCodec(backend.mtu)
	if err != nil {
		_ = conn.Close()
		return nil, transport.Wrap("open ble session", transport.ClassifyCommon(err))
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
	session.mu.Lock()
	defer session.mu.Unlock()

	fragments, err := session.codec.Fragment(req)
	if err != nil {
		return nil, transport.Wrap("fragment ble request", transport.ClassifyCommon(err))
	}
	for _, fragment := range fragments {
		if err := session.conn.WriteFragment(ctx, fragment); err != nil {
			return nil, transport.Wrap("write ble fragment", transport.ClassifyCommon(err))
		}
	}

	assembler := session.codec.NewAssembler()
	for !assembler.Done() {
		fragment, err := session.conn.ReadFragment(ctx)
		if err != nil {
			return nil, transport.Wrap("read ble fragment", transport.ClassifyCommon(err))
		}
		if err := assembler.Add(fragment); err != nil {
			return nil, transport.Wrap("reassemble ble response", transport.ClassifyCommon(err))
		}
	}

	response, err := assembler.Payload()
	if err != nil {
		return nil, transport.Wrap("reassemble ble response", transport.ClassifyCommon(err))
	}
	return response, nil
}

// Close closes the underlying BLE connection.
func (session *Session) Close() error {
	if err := session.conn.Close(); err != nil {
		return transport.Wrap("close ble session", transport.ClassifyCommon(err))
	}
	return nil
}
