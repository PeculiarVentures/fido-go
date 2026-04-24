package usb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
	hid "github.com/sstallion/go-hid"
)

const (
	hidReportSize       = 64
	hidBroadcastCID     = 0xffffffff
	hidCommandInit      = 0x86
	hidCommandMsg       = 0x83
	hidCommandCBOR      = 0x90
	hidCommandKeepalive = 0xbb
	hidCommandError     = 0xbf
	fidoUsagePage       = 0xf1d0
	fidoUsage           = 0x01
)

// HIDBackend discovers and opens real USB HID FIDO authenticators.
type HIDBackend struct{}

// HIDError reports a CTAPHID ERROR response returned by an authenticator.
type HIDError struct {
	Code byte
}

// Error returns the wire-level CTAPHID error code.
func (err *HIDError) Error() string {
	if err == nil {
		return "transport/usb: <nil>"
	}
	return fmt.Sprintf("transport/usb: CTAPHID error 0x%02x", err.Code)
}

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
		return nil, transport.Wrap("discover usb hid devices", classifyHIDError(err))
	}
	return devices, nil
}

// Open opens a USB HID session for the specified FIDO authenticator.
func (backend *HIDBackend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, transport.Wrap("open usb hid session", classifyHIDError(err))
	}

	opened, err := openHIDDevice(device)
	if err != nil {
		return nil, transport.Wrap("open usb hid session", classifyHIDError(err))
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
		return nil, transport.Wrap("initialize usb hid channel", classifyHIDError(err))
	}
	command := hidCommandForRequest(req)
	codec, err := wirehid.NewCodec(session.channelID, command, session.reportSize)
	if err != nil {
		return nil, transport.Wrap("fragment usb hid request", classifyHIDError(err))
	}
	packets, err := codec.Fragment(req)
	if err != nil {
		return nil, transport.Wrap("fragment usb hid request", classifyHIDError(err))
	}
	for _, packet := range packets {
		if err := session.writePacket(ctx, packet); err != nil {
			return nil, transport.Wrap("write usb hid packet", classifyHIDError(err))
		}
	}
	response, err := session.readMessage(ctx, session.channelID, command)
	if err != nil {
		return nil, transport.Wrap("read usb hid response", classifyHIDError(err))
	}
	return response, nil
}

// Close closes the underlying HID device.
func (session *hidSession) Close() error {
	if session.dev == nil {
		return nil
	}
	if err := session.dev.Close(); err != nil {
		return transport.Wrap("close usb hid session", classifyHIDError(err))
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
	return readHIDMessage(ctx, session.reportSize, channelID, command, session.readPacket)
}

func readHIDMessage(ctx context.Context, reportSize int, channelID uint32, command byte, readPacket func(context.Context) ([]byte, error)) ([]byte, error) {
	codec, err := wirehid.NewCodec(channelID, command, reportSize)
	if err != nil {
		return nil, err
	}
	assembler := codec.NewAssembler()
	firstPacket := true
	for !assembler.Done() {
		packet, err := readPacket(ctx)
		if err != nil {
			return nil, err
		}
		if firstPacket && isHIDKeepalivePacket(packet, reportSize, channelID) {
			if err := discardHIDMessage(ctx, reportSize, channelID, hidCommandKeepalive, packet, readPacket); err != nil {
				return nil, err
			}
			continue
		}
		if firstPacket && isHIDCommandPacket(packet, reportSize, channelID, hidCommandError) {
			return nil, readHIDError(ctx, reportSize, channelID, packet, readPacket)
		}
		if err := assembler.Add(packet); err != nil {
			return nil, err
		}
		firstPacket = false
	}
	return assembler.Payload()
}

func discardHIDMessage(ctx context.Context, reportSize int, channelID uint32, command byte, firstPacket []byte, readPacket func(context.Context) ([]byte, error)) error {
	codec, err := wirehid.NewCodec(channelID, command, reportSize)
	if err != nil {
		return err
	}
	assembler := codec.NewAssembler()
	if err := assembler.Add(firstPacket); err != nil {
		return err
	}
	for !assembler.Done() {
		packet, err := readPacket(ctx)
		if err != nil {
			return err
		}
		if err := assembler.Add(packet); err != nil {
			return err
		}
	}
	_, err = assembler.Payload()
	return err
}

func isHIDKeepalivePacket(packet []byte, reportSize int, channelID uint32) bool {
	return isHIDCommandPacket(packet, reportSize, channelID, hidCommandKeepalive)
}

func isHIDCommandPacket(packet []byte, reportSize int, channelID uint32, command byte) bool {
	if len(packet) != reportSize {
		return false
	}
	if binary.BigEndian.Uint32(packet[:4]) != channelID {
		return false
	}
	return packet[4] == command
}

func (session *hidSession) writePacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.dev == nil {
		return transport.Disconnected(errors.New("transport/usb: hid device is closed"))
	}
	report := make([]byte, len(packet)+1)
	copy(report[1:], packet)
	dev := session.dev
	written, err := runCancelableHIDCall(ctx, func() (int, error) {
		return dev.Write(report)
	}, dev.Close)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		session.dev = nil
		return err
	}
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
	if session.dev == nil {
		return nil, transport.Disconnected(errors.New("transport/usb: hid device is closed"))
	}
	buffer := make([]byte, session.reportSize+1)
	dev := session.dev
	read, err := runCancelableHIDCall(ctx, func() (int, error) {
		return dev.Read(buffer)
	}, dev.Close)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		session.dev = nil
		return nil, err
	}
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

func readHIDError(ctx context.Context, reportSize int, channelID uint32, firstPacket []byte, readPacket func(context.Context) ([]byte, error)) error {
	codec, err := wirehid.NewCodec(channelID, hidCommandError, reportSize)
	if err != nil {
		return err
	}
	assembler := codec.NewAssembler()
	if err := assembler.Add(firstPacket); err != nil {
		return err
	}
	for !assembler.Done() {
		packet, err := readPacket(ctx)
		if err != nil {
			return err
		}
		if err := assembler.Add(packet); err != nil {
			return err
		}
	}
	payload, err := assembler.Payload()
	if err != nil {
		return err
	}
	if len(payload) != 1 {
		return fmt.Errorf("transport/usb: invalid CTAPHID error payload length %d", len(payload))
	}
	return &HIDError{Code: payload[0]}
}

type hidCallResult[T any] struct {
	value T
	err   error
}

func runCancelableHIDCall[T any](ctx context.Context, call func() (T, error), closeFn func() error) (T, error) {
	var zero T
	resultCh := make(chan hidCallResult[T], 1)
	go func() {
		value, err := call()
		resultCh <- hidCallResult[T]{value: value, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-ctx.Done():
		_ = closeFn()
		return zero, ctx.Err()
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

func classifyHIDError(err error) error {
	err = transport.ClassifyCommon(err)
	if err == nil || errors.Is(err, transport.ErrDisconnected) || errors.Is(err, transport.ErrPermissionDenied) || errors.Is(err, transport.ErrTemporary) || errors.Is(err, transport.ErrUnsupported) {
		return err
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "device was not found"), strings.Contains(message, "iokit/common"), strings.Contains(message, "general error"), strings.Contains(message, "no such device"):
		return transport.Disconnected(err)
	case strings.Contains(message, "permission denied"), strings.Contains(message, "operation not permitted"), strings.Contains(message, "access denied"):
		return transport.PermissionDenied(err)
	default:
		return err
	}
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
