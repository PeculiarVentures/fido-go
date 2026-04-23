package nfc

import (
	"context"
	"fmt"

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
	if err != nil {
		return nil, &transport.Error{Op: "discover nfc devices", Err: err}
	}
	for index := range devices {
		devices[index].Transport = transport.KindNFC
	}
	return devices, nil
}

// Open opens an NFC session for the descriptor.
func (backend *Backend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindNFC {
		return nil, &transport.Error{Op: "open nfc session", Err: fmt.Errorf("transport/nfc: unsupported transport %s", device.Transport)}
	}
	conn, err := backend.opener.Open(ctx, device)
	if err != nil {
		return nil, &transport.Error{Op: "open nfc session", Err: err}
	}
	codec, err := wirenfc.NewCodec(backend.class, backend.ins, backend.p1, backend.p2, backend.chunkSize)
	if err != nil {
		_ = conn.Close()
		return nil, &transport.Error{Op: "open nfc session", Err: err}
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
	if isAPDURequest(req) {
		response, err := session.conn.Transceive(ctx, req)
		if err != nil {
			return nil, &transport.Error{Op: "transceive nfc apdu", Err: err}
		}
		return session.readAPDUResponse(ctx, response)
	}

	packets, err := session.codec.Fragment(req)
	if err != nil {
		return nil, &transport.Error{Op: "fragment nfc request", Err: err}
	}

	assembler := session.codec.NewAssembler()
	for index, packet := range packets {
		response, err := session.conn.Transceive(ctx, packet)
		if err != nil {
			return nil, &transport.Error{Op: "transceive nfc packet", Err: err}
		}
		if index < len(packets)-1 {
			if err := session.codec.ValidateInterimResponse(response); err != nil {
				return nil, &transport.Error{Op: "validate nfc chain response", Err: err}
			}
			continue
		}
		if err := assembler.Add(response); err != nil {
			return nil, &transport.Error{Op: "reassemble nfc response", Err: err}
		}
	}

	for !assembler.Done() {
		response, err := session.conn.Transceive(ctx, session.codec.GetResponsePacket(assembler.MoreDataHint()))
		if err != nil {
			return nil, &transport.Error{Op: "continue nfc response", Err: err}
		}
		if err := assembler.Add(response); err != nil {
			return nil, &transport.Error{Op: "reassemble nfc response", Err: err}
		}
	}

	decoded, err := assembler.Payload()
	if err != nil {
		return nil, &transport.Error{Op: "reassemble nfc response", Err: err}
	}
	return decoded, nil
}

func (session *Session) readAPDUResponse(ctx context.Context, response []byte) ([]byte, error) {
	if len(response) < 2 {
		return nil, &transport.Error{Op: "read nfc apdu response", Err: fmt.Errorf("transport/nfc: response is too short")}
	}

	buffer := append([]byte(nil), response[:len(response)-2]...)
	status1 := response[len(response)-2]
	status2 := response[len(response)-1]

	for status1 == 0x61 {
		nextResponse, err := session.conn.Transceive(ctx, session.codec.GetResponsePacket(status2))
		if err != nil {
			return nil, &transport.Error{Op: "continue nfc apdu response", Err: err}
		}
		if len(nextResponse) < 2 {
			return nil, &transport.Error{Op: "read nfc apdu response", Err: fmt.Errorf("transport/nfc: response is too short")}
		}
		buffer = append(buffer, nextResponse[:len(nextResponse)-2]...)
		status1 = nextResponse[len(nextResponse)-2]
		status2 = nextResponse[len(nextResponse)-1]
	}

	if status1 != 0x90 || status2 != 0x00 {
		return nil, &transport.Error{Op: "read nfc apdu response", Err: fmt.Errorf("transport/nfc: unexpected APDU status 0x%02x%02x", status1, status2)}
	}

	return append(buffer, status1, status2), nil
}

// Close closes the underlying NFC transceiver.
func (session *Session) Close() error {
	if err := session.conn.Close(); err != nil {
		return &transport.Error{Op: "close nfc session", Err: err}
	}
	return nil
}

func isAPDURequest(req []byte) bool {
	return len(req) >= 4 && req[0] == 0x00
}
