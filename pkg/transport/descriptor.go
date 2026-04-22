package transport

import "fmt"

// Kind identifies the transport used to talk to an authenticator.
type Kind string

const (
	// KindUSB identifies USB HID transports.
	KindUSB Kind = "usb"
	// KindNFC identifies NFC transports.
	KindNFC Kind = "nfc"
	// KindBLE identifies BLE transports.
	KindBLE Kind = "ble"
	// KindUnknown is used when the concrete transport is not yet known.
	KindUnknown Kind = "unknown"
)

// DeviceDescriptor describes one discovered authenticator endpoint.
type DeviceDescriptor struct {
	ID           string
	Transport    Kind
	Path         string
	Manufacturer string
	Product      string
	SerialNumber string
	VendorID     uint16
	ProductID    uint16
}

// DisplayName returns a stable human-readable device label.
func (device DeviceDescriptor) DisplayName() string {
	switch {
	case device.Product != "" && device.SerialNumber != "":
		return fmt.Sprintf("%s (%s)", device.Product, device.SerialNumber)
	case device.Product != "":
		return device.Product
	case device.ID != "":
		return device.ID
	default:
		return string(device.Transport)
	}
}
