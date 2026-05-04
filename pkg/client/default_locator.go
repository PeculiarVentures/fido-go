package client

import (
	"errors"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportnfc "github.com/PeculiarVentures/fido-go/pkg/transport/nfc"
	transportusb "github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

var (
	newDefaultUSBBackend               = func() transport.Backend { return transportusb.NewHIDBackend() }
	newDefaultNFCBackend               = func() (transport.Backend, error) { return transportnfc.NewPCSCBackend() }
	errDefaultLocatorTransportRequired = errors.New("client: at least one default transport must be enabled")
)

// TransportPreference controls which transports NewDefaultLocator enables.
type TransportPreference struct {
	USB bool
	NFC bool
}

// LocatorOption configures the behavior of NewDefaultLocator.
type LocatorOption func(*locatorOptions)

type locatorOptions struct {
	preference TransportPreference
}

// WithUSB enables or disables USB HID discovery for NewDefaultLocator.
func WithUSB(enabled bool) LocatorOption {
	return func(options *locatorOptions) {
		options.preference.USB = enabled
	}
}

// WithNFC enables or disables NFC/PCSC discovery for NewDefaultLocator.
func WithNFC(enabled bool) LocatorOption {
	return func(options *locatorOptions) {
		options.preference.NFC = enabled
	}
}

// NewDefaultLocator builds the default public locator for local authenticators.
//
// By default it enables USB HID only. NFC/PCSC discovery is an explicit opt-in
// through WithNFC(true) because probing PC/SC readers can have side effects for
// other smart-card stacks already using the same token.
func NewDefaultLocator(options ...LocatorOption) (Locator, error) {
	resolved := defaultLocatorOptions()
	for _, option := range options {
		if option != nil {
			option(&resolved)
		}
	}

	backends := make([]transport.Backend, 0, 2)
	if resolved.preference.USB {
		backends = append(backends, newDefaultUSBBackend())
	}
	if resolved.preference.NFC {
		nfcBackend, err := newDefaultNFCBackend()
		if err != nil {
			return nil, err
		}
		backends = append(backends, nfcBackend)
	}
	if len(backends) == 0 {
		return nil, errDefaultLocatorTransportRequired
	}

	return NewTransportLocator(backends...)
}

func defaultLocatorOptions() locatorOptions {
	return locatorOptions{preference: TransportPreference{USB: true}}
}
