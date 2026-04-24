package nfc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	pivpcsc "github.com/PeculiarVentures/piv-go/pcsc"
)

const (
	defaultAPDUClass       byte = 0x80
	defaultAPDUInstruction byte = 0x10
	defaultAPDUParameter1  byte = 0x00
	defaultAPDUParameter2  byte = 0x00
	defaultAPDUChunkSize        = 240
)

var fidoAppletSelectCommand = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00}

// PCSCContext abstracts the small subset of PC/SC context operations needed by the NFC transport.
type PCSCContext interface {
	ListReaders() ([]string, error)
	Connect(reader string) (PCSCCard, error)
	Release() error
}

// PCSCCard abstracts the APDU-capable PC/SC card handle used by the NFC transport.
type PCSCCard interface {
	Transmit(command []byte) ([]byte, error)
	Close() error
}

// PCSCContextFactory constructs a PC/SC context for one discovery or open operation.
type PCSCContextFactory func() (PCSCContext, error)

type pcscDiscoverer struct {
	factory PCSCContextFactory
}

type pcscOpener struct {
	factory PCSCContextFactory
}

type pcscTransceiver struct {
	context PCSCContext
	card    PCSCCard
}

type defaultPCSCContext struct {
	context *pivpcsc.Context
}

type defaultPCSCCard struct {
	card *pivpcsc.Card
}

// NewPCSCBackend creates an NFC backend backed by the local PC/SC resource manager.
func NewPCSCBackend() (*Backend, error) {
	return NewPCSCBackendWithFactory(func() (PCSCContext, error) {
		context, err := pivpcsc.NewContext()
		if err != nil {
			return nil, err
		}
		return &defaultPCSCContext{context: context}, nil
	})
}

// NewPCSCBackendWithFactory creates an NFC backend using the provided PC/SC context factory.
func NewPCSCBackendWithFactory(factory PCSCContextFactory) (*Backend, error) {
	if factory == nil {
		return nil, fmt.Errorf("transport/nfc: pcsc context factory is required")
	}
	return NewBackend(
		&pcscDiscoverer{factory: factory},
		&pcscOpener{factory: factory},
		defaultAPDUClass,
		defaultAPDUInstruction,
		defaultAPDUParameter1,
		defaultAPDUParameter2,
		defaultAPDUChunkSize,
	)
}

func (discoverer *pcscDiscoverer) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pcscContext, err := discoverer.factory()
	if err != nil {
		return nil, err
	}
	defer func() { _ = pcscContext.Release() }()

	readers, err := pcscContext.ListReaders()
	if err != nil {
		return nil, err
	}

	devices := make([]transport.DeviceDescriptor, 0, len(readers))
	var errs []error
	for _, reader := range readers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		version, ok, err := probePCSCReader(pcscContext, reader)
		if err != nil {
			errs = append(errs, fmt.Errorf("transport/nfc: probe reader %q: %w", reader, err))
			continue
		}
		if !ok {
			continue
		}
		devices = append(devices, newPCSCDeviceDescriptor(reader, version))
	}
	if len(errs) > 0 {
		return devices, errors.Join(errs...)
	}
	return devices, nil
}

func (opener *pcscOpener) Open(ctx context.Context, device transport.DeviceDescriptor) (Transceiver, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader := strings.TrimSpace(device.Path)
	if reader == "" {
		reader = strings.TrimPrefix(strings.TrimSpace(device.ID), "pcsc:")
	}
	if reader == "" {
		return nil, fmt.Errorf("transport/nfc: PC/SC reader path is required")
	}

	pcscContext, err := opener.factory()
	if err != nil {
		return nil, err
	}
	card, err := pcscContext.Connect(reader)
	if err != nil {
		_ = pcscContext.Release()
		return nil, err
	}
	if _, err := selectFIDOApplet(card); err != nil {
		_ = card.Close()
		_ = pcscContext.Release()
		return nil, err
	}
	return &pcscTransceiver{context: pcscContext, card: card}, nil
}

func (transceiver *pcscTransceiver) Transceive(ctx context.Context, packet []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return transceiver.card.Transmit(packet)
}

func (transceiver *pcscTransceiver) Close() error {
	cardErr := transceiver.card.Close()
	contextErr := transceiver.context.Release()
	if cardErr != nil {
		return cardErr
	}
	return contextErr
}

func (context *defaultPCSCContext) ListReaders() ([]string, error) {
	return context.context.ListReaders()
}

func (context *defaultPCSCContext) Connect(reader string) (PCSCCard, error) {
	card, err := context.context.Connect(reader)
	if err != nil {
		return nil, err
	}
	return &defaultPCSCCard{card: card}, nil
}

func (context *defaultPCSCContext) Release() error {
	return context.context.Release()
}

func (card *defaultPCSCCard) Transmit(command []byte) ([]byte, error) {
	return card.card.Transmit(command)
}

func (card *defaultPCSCCard) Close() error {
	return card.card.Close()
}

func probePCSCReader(pcscContext PCSCContext, reader string) ([]byte, bool, error) {
	card, err := pcscContext.Connect(reader)
	if err != nil {
		if shouldIgnorePCSCConnectError(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = card.Close() }()

	version, err := selectFIDOApplet(card)
	if err != nil {
		var selectErr *appletSelectionError
		if errors.As(err, &selectErr) && selectErr.SW1 == 0x6A && selectErr.SW2 == 0x82 {
			return nil, false, nil
		}
		return nil, false, err
	}
	return version, true, nil
}

func selectFIDOApplet(card PCSCCard) ([]byte, error) {
	response, err := card.Transmit(fidoAppletSelectCommand)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, fmt.Errorf("transport/nfc: applet selection response is too short")
	}
	status1 := response[len(response)-2]
	status2 := response[len(response)-1]
	if status1 != 0x90 || status2 != 0x00 {
		return nil, &appletSelectionError{SW1: status1, SW2: status2}
	}
	return append([]byte(nil), response[:len(response)-2]...), nil
}

type appletSelectionError struct {
	SW1 byte
	SW2 byte
}

func (err *appletSelectionError) Error() string {
	if err == nil {
		return "transport/nfc: <nil>"
	}
	return fmt.Sprintf("transport/nfc: FIDO applet selection failed with status 0x%02x%02x", err.SW1, err.SW2)
}

func shouldIgnorePCSCConnectError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no card")
}

func newPCSCDeviceDescriptor(reader string, version []byte) transport.DeviceDescriptor {
	name := strings.TrimSpace(reader)
	if name == "" {
		name = "PC/SC reader"
	}
	versionText := strings.TrimSpace(string(version))
	product := name
	if versionText != "" {
		product = fmt.Sprintf("%s [%s]", name, versionText)
	}
	return transport.DeviceDescriptor{
		ID:        "pcsc:" + name,
		Transport: transport.KindNFC,
		Path:      name,
		Product:   product,
	}
}
