package client

import (
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportnfc "github.com/PeculiarVentures/fido-go/pkg/transport/nfc"
	transportusb "github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

var (
	newDefaultUSBBackend = func() transport.Backend { return transportusb.NewHIDBackend() }
	newDefaultNFCBackend = func() (transport.Backend, error) { return transportnfc.NewPCSCBackend() }
)

// NewDefaultLocator builds the default public locator for local USB HID and NFC authenticators.
func NewDefaultLocator() (Locator, error) {
	backends := []transport.Backend{newDefaultUSBBackend()}

	nfcBackend, err := newDefaultNFCBackend()
	if err == nil {
		backends = append(backends, nfcBackend)
	}

	return NewTransportLocator(backends...)
}
