package client

import transportusb "github.com/PeculiarVentures/fido-go/pkg/transport/usb"

// NewDefaultLocator builds the default public locator for local USB FIDO HID devices.
func NewDefaultLocator() (Locator, error) {
	return NewTransportLocator(transportusb.NewHIDBackend())
}
