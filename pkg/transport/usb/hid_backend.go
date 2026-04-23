package usb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
	hid "github.com/sstallion/go-hid"
)

const (
	hidReportSize   = 64
	hidBroadcastCID = 0xffffffff
	hidCommandInit  = 0x86
	hidCommandMsg   = 0x83
	hidCommandCBOR  = 0x90
	fidoUsagePage   = 0xf1d0
	fidoUsage       = 0x01
)

// HIDBackend discovers and opens real USB HID FIDO authenticators.
type HIDBackend struct{}

type hidSession struct {
	mu         sync.Mutex
	device     transport.DeviceDescriptor
	dev        *hid.Device
	channelID  uint32
	reportSize int
}

// NewHIDBackend creates a USB HID backend for locally attached FIDO devices.
func NewHIDBackend() *HIDBackend {
	return &HIDBackend{}
}

// Kind returns the USB transport kind.
func (backend *HIDBackend) Kind() transport.Kind {
	return transport.KindUSB
}

// Discover enumerates USB HID devices that expose the FIDO usage page.
func (backend *HIDBackend) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	var devices []transport.DeviceDescriptor
	err := hid.Enumerate(0, 0, func(info *hid.DeviceInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !isFIDOHIDDevice(info) {
			return nil
		}
		devices = append(devices, transport.DeviceDescriptor{
			ID:           info.Path,
			Transport:    transport.KindUSB,
			Path:         info.Path,
			Manufacturer: info.MfrStr,
			Product:      info.ProductStr,
			SerialNumber: info.SerialNbr,
			VendorID:     info.VendorID,
			ProductID:    info.ProductID,
		})
		return nil
	})
	if err != nil {
		return nil, &transport.Error{Op: "discover usb hid devices", Err: err}
	}
	return devices, nil
}

// Open opens a USB HID session for the specified FIDO authenticator.
func (backend *HIDBackend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, &transport.Error{Op: "open usb hid session", Err: err}
	}

	opened, err := openHIDDevice(device)
	if err != nil {
		return nil, &transport.Error{Op: "open usb hid session", Err: err}
	}
	device.Transport = transport.KindUSB
	if device.ID == "" {
		device.ID = device.Path
	}
	return &hidSession{device: device, dev: opened, reportSize: hidReportSize}, nil
}

// Device returns the opened USB HID descriptor.
func (session *hidSession) Device() transport.DeviceDescriptor {
	return session.device
}

// Exchange sends one CTAP request over CTAPHID and returns the complete response payload.
func (session *hidSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	if err := session.ensureChannel(ctx); err != nil {
		return nil, &transport.Error{Op: "initialize usb hid channel", Err: err}
	}
	command := hidCommandForRequest(req)
	codec, err := wirehid.NewCodec(session.channelID, command, session.reportSize)
	if err != nil {
		return nil, &transport.Error{Op: "fragment usb hid request", Err: err}
	}
	packets, err := codec.Fragment(req)
	if err != nil {
		return nil, &transport.Error{Op: "fragment usb hid request", Err: err}
	}
	for _, packet := range packets {
		if err := session.writePacket(ctx, packet); err != nil {
			return nil, &transport.Error{Op: "write usb hid packet", Err: err}
		}
	}
	response, err := session.readMessage(ctx, session.channelID, command)
	if err != nil {
		return nil, &transport.Error{Op: "read usb hid response", Err: err}
	}
	return response, nil
}

// Close closes the underlying HID device.
func (session *hidSession) Close() error {
	if session.dev == nil {
		return nil
	}
	if err := session.dev.Close(); err != nil {
		return &transport.Error{Op: "close usb hid session", Err: err}
	}
	session.dev = nil
	return nil
}

func (session *hidSession) ensureChannel(ctx context.Context) error {
	if session.channelID != 0 {
		return nil
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	codec, err := wirehid.NewCodec(hidBroadcastCID, hidCommandInit, session.reportSize)
	if err != nil {
		return err
	}
	packets, err := codec.Fragment(nonce)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if err := session.writePacket(ctx, packet); err != nil {
			return err
		}
	}
	response, err := session.readMessage(ctx, hidBroadcastCID, hidCommandInit)
	if err != nil {
		return err
	}
	if len(response) < 12 {
		return fmt.Errorf("transport/usb: init response is too short")
	}
	if !bytes.Equal(response[:8], nonce) {
		return fmt.Errorf("transport/usb: init nonce mismatch")
	}
	session.channelID = binary.BigEndian.Uint32(response[8:12])
	return nil
}

func (session *hidSession) readMessage(ctx context.Context, channelID uint32, command byte) ([]byte, error) {
	codec, err := wirehid.NewCodec(channelID, command, session.reportSize)
	if err != nil {
		return nil, err
	}
	assembler := codec.NewAssembler()
	for !assembler.Done() {
		packet, err := session.readPacket(ctx)
		if err != nil {
			return nil, err
		}
		if err := assembler.Add(packet); err != nil {
			return nil, err
		}
	}
	return assembler.Payload()
}

func (session *hidSession) writePacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	report := make([]byte, len(packet)+1)
	copy(report[1:], packet)
	written, err := session.dev.Write(report)
	if err != nil {
		return err
	}
	if written != len(report) {
		return fmt.Errorf("transport/usb: short hid write %d/%d", written, len(report))
	}
	return nil
}

func (session *hidSession) readPacket(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buffer := make([]byte, session.reportSize+1)
	read, err := session.dev.Read(buffer)
	if err != nil {
		return nil, err
	}
	switch {
	case read >= session.reportSize+1:
		return append([]byte(nil), buffer[1:1+session.reportSize]...), nil
	case read >= session.reportSize:
		return append([]byte(nil), buffer[:session.reportSize]...), nil
	default:
		return nil, fmt.Errorf("transport/usb: short hid read %d", read)
	}
}

func openHIDDevice(device transport.DeviceDescriptor) (*hid.Device, error) {
	if device.Path != "" {
		opened, err := hid.OpenPath(device.Path)
		if err == nil {
			return opened, nil
		}
		if device.VendorID == 0 || device.ProductID == 0 {
			return nil, err
		}
	}
	if device.VendorID == 0 || device.ProductID == 0 {
		return nil, fmt.Errorf("transport/usb: device path or vendor/product ids are required")
	}
	return hid.OpenFirst(device.VendorID, device.ProductID)
}

func isFIDOHIDDevice(info *hid.DeviceInfo) bool {
	if info.UsagePage == fidoUsagePage && info.Usage == fidoUsage {
		return true
	}
	return info.UsagePage == 0 && info.Usage == 0 && info.InterfaceNbr >= 0 && info.ProductStr != ""
}

func hidCommandForRequest(req []byte) byte {
	if isCTAP1APDU(req) {
		return hidCommandMsg
	}
	return hidCommandCBOR
}

func isCTAP1APDU(req []byte) bool {
	if len(req) < 4 || req[0] != 0x00 {
		return false
	}
	switch req[1] {
	case 0x01, 0x02, 0x03:
		return true
	default:
		return false
	}
}
