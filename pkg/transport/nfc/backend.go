package nfc

import (
	"context"
	"fmt"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirenfc "github.com/PeculiarVentures/fido-go/pkg/wire/nfc"
)

// Transceiver exchanges one APDU packet at a time.
type Transceiver interface {
	Transceive(ctx context.Context, packet []byte) ([]byte, error)
	Close() error
}

// Discoverer lists NFC transport descriptors without opening sessions.
type Discoverer interface {
	Discover(ctx context.Context) ([]transport.DeviceDescriptor, error)
}

// Opener opens an NFC transceiver for a descriptor.
type Opener interface {
	Open(ctx context.Context, device transport.DeviceDescriptor) (Transceiver, error)
}

// Backend discovers and opens NFC transport sessions.
type Backend struct {
	discoverer Discoverer
	opener     Opener
	class      byte
	ins        byte
	p1         byte
	p2         byte
	chunkSize  int
}

// Session exchanges complete payloads over an APDU transceiver.
type Session struct {
	mu     sync.Mutex
	device transport.DeviceDescriptor
	conn   Transceiver
	codec  *wirenfc.Codec
}

// NewBackend creates an NFC backend with injected discovery and APDU hooks.
func NewBackend(discoverer Discoverer, opener Opener, class, instruction, parameter1, parameter2 byte, chunkSize int) (*Backend, error) {
	if discoverer == nil || opener == nil {
		return nil, fmt.Errorf("transport/nfc: discoverer and opener are required")
	}
	if _, err := wirenfc.NewCodec(class, instruction, parameter1, parameter2, chunkSize); err != nil {
		return nil, err
	}
	return &Backend{discoverer: discoverer, opener: opener, class: class, ins: instruction, p1: parameter1, p2: parameter2, chunkSize: chunkSize}, nil
}

// Kind returns the NFC transport kind.
func (backend *Backend) Kind() transport.Kind {
	return transport.KindNFC
}

// Discover lists NFC descriptors and normalizes their transport kind.
func (backend *Backend) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	devices, err := backend.discoverer.Discover(ctx)
	for index := range devices {
		devices[index].Transport = transport.KindNFC
	}
	if err != nil {
		return devices, transport.Wrap("discover nfc devices", transport.ClassifyCommon(err))
	}
	return devices, nil
}

// Open opens an NFC session for the descriptor.
func (backend *Backend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindNFC {
		return nil, transport.Wrap("open nfc session", transport.Unsupported(fmt.Errorf("transport/nfc: unsupported transport %s", device.Transport)))
	}
	conn, err := backend.opener.Open(ctx, device)
	if err != nil {
		return nil, transport.Wrap("open nfc session", transport.ClassifyCommon(err))
	}
	codec, err := wirenfc.NewCodec(backend.class, backend.ins, backend.p1, backend.p2, backend.chunkSize)
	if err != nil {
		_ = conn.Close()
		return nil, transport.Wrap("open nfc session", transport.ClassifyCommon(err))
	}
	device.Transport = transport.KindNFC
	return &Session{device: device, conn: conn, codec: codec}, nil
}

// Device returns the bound descriptor.
func (session *Session) Device() transport.DeviceDescriptor {
	return session.device
}

// Exchange writes chained APDUs when needed and reassembles chained responses.
func (session *Session) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	packets, err := session.codec.Fragment(req)
	if err != nil {
		return nil, transport.Wrap("fragment nfc request", transport.ClassifyCommon(err))
	}

	assembler := session.codec.NewAssembler()
	for index, packet := range packets {
		response, err := session.conn.Transceive(ctx, packet)
		if err != nil {
			return nil, transport.Wrap("transceive nfc packet", transport.ClassifyCommon(err))
		}
		if index < len(packets)-1 {
			if err := session.codec.ValidateInterimResponse(response); err != nil {
				return nil, transport.Wrap("validate nfc chain response", transport.ClassifyCommon(err))
			}
			continue
		}
		if err := assembler.Add(response); err != nil {
			return nil, transport.Wrap("reassemble nfc response", transport.ClassifyCommon(err))
		}
	}

	for !assembler.Done() {
		response, err := session.conn.Transceive(ctx, session.codec.GetResponsePacket(assembler.MoreDataHint()))
		if err != nil {
			return nil, transport.Wrap("continue nfc response", transport.ClassifyCommon(err))
		}
		if err := assembler.Add(response); err != nil {
			return nil, transport.Wrap("reassemble nfc response", transport.ClassifyCommon(err))
		}
	}

	decoded, err := assembler.Payload()
	if err != nil {
		return nil, transport.Wrap("reassemble nfc response", transport.ClassifyCommon(err))
	}
	return decoded, nil
}

// Close closes the underlying NFC transceiver.
func (session *Session) Close() error {
	if err := session.conn.Close(); err != nil {
		return transport.Wrap("close nfc session", transport.ClassifyCommon(err))
	}
	return nil
}
