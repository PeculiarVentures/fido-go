package usb

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

// PacketConn sends and receives one HID packet at a time.
type PacketConn interface {
	WritePacket(ctx context.Context, packet []byte) error
	ReadPacket(ctx context.Context) ([]byte, error)
	Close() error
}

// Discoverer lists USB transport descriptors without opening sessions.
type Discoverer interface {
	Discover(ctx context.Context) ([]transport.DeviceDescriptor, error)
}

// Opener opens a USB packet connection for a descriptor.
type Opener interface {
	Open(ctx context.Context, device transport.DeviceDescriptor) (PacketConn, error)
}

// Backend discovers and opens USB HID transport sessions.
type Backend struct {
	discoverer Discoverer
	opener     Opener
	channel    uint32
	command    byte
	reportSize int
}

// Session exchanges complete payloads over a USB HID packet connection.
type Session struct {
	device transport.DeviceDescriptor
	conn   PacketConn
	codec  *wirehid.Codec
}

// NewBackend creates a USB backend with injected discovery and connection hooks.
func NewBackend(discoverer Discoverer, opener Opener, channel uint32, command byte, reportSize int) (*Backend, error) {
	if discoverer == nil || opener == nil {
		return nil, fmt.Errorf("transport/usb: discoverer and opener are required")
	}
	if _, err := wirehid.NewCodec(channel, command, reportSize); err != nil {
		return nil, err
	}
	return &Backend{discoverer: discoverer, opener: opener, channel: channel, command: command, reportSize: reportSize}, nil
}

// Kind returns the USB transport kind.
func (backend *Backend) Kind() transport.Kind {
	return transport.KindUSB
}

// Discover lists USB descriptors and normalizes their transport kind.
func (backend *Backend) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	devices, err := backend.discoverer.Discover(ctx)
	if err != nil {
		return nil, &transport.Error{Op: "discover usb devices", Err: err}
	}
	for index := range devices {
		devices[index].Transport = transport.KindUSB
	}
	return devices, nil
}

// Open opens a USB HID session for the descriptor.
func (backend *Backend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindUSB {
		return nil, &transport.Error{Op: "open usb session", Err: fmt.Errorf("transport/usb: unsupported transport %s", device.Transport)}
	}
	conn, err := backend.opener.Open(ctx, device)
	if err != nil {
		return nil, &transport.Error{Op: "open usb session", Err: err}
	}
	codec, err := wirehid.NewCodec(backend.channel, backend.command, backend.reportSize)
	if err != nil {
		_ = conn.Close()
		return nil, &transport.Error{Op: "open usb session", Err: err}
	}
	device.Transport = transport.KindUSB
	return &Session{device: device, conn: conn, codec: codec}, nil
}

// Device returns the bound device descriptor.
func (session *Session) Device() transport.DeviceDescriptor {
	return session.device
}

// Exchange writes a full USB HID request and reassembles the full response.
func (session *Session) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	packets, err := session.codec.Fragment(req)
	if err != nil {
		return nil, &transport.Error{Op: "fragment usb request", Err: err}
	}
	for _, packet := range packets {
		if err := session.conn.WritePacket(ctx, packet); err != nil {
			return nil, &transport.Error{Op: "write usb packet", Err: err}
		}
	}

	assembler := session.codec.NewAssembler()
	for !assembler.Done() {
		packet, err := session.conn.ReadPacket(ctx)
		if err != nil {
			return nil, &transport.Error{Op: "read usb packet", Err: err}
		}
		if err := assembler.Add(packet); err != nil {
			return nil, &transport.Error{Op: "reassemble usb response", Err: err}
		}
	}

	response, err := assembler.Payload()
	if err != nil {
		return nil, &transport.Error{Op: "reassemble usb response", Err: err}
	}
	return response, nil
}

// Close closes the underlying USB connection.
func (session *Session) Close() error {
	if err := session.conn.Close(); err != nil {
		return &transport.Error{Op: "close usb session", Err: err}
	}
	return nil
}
