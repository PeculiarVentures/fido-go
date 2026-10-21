package usb

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// HIDSession optionally extends a transport session with explicit CTAPHID messages.
// Commands are logical seven-bit values, not packet command bytes: use 0x42,
// not 0xc2. Payloads and responses exclude HID headers and are not interpreted.
// INIT and CANCEL belong to the session; ERROR and KEEPALIVE are response-only.
// Exchange and ExchangeHID share the session's channel and serialization.
type HIDSession interface {
	transport.Session
	ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error)
}

// InvalidHIDCommandError reports an encoded, zero, or session-owned HID command.
type InvalidHIDCommandError struct {
	Command byte
}

// Error returns the rejected logical CTAPHID command.
func (err *InvalidHIDCommandError) Error() string {
	if err == nil {
		return "transport/usb: invalid logical CTAPHID command"
	}
	return fmt.Sprintf("transport/usb: invalid logical CTAPHID request command 0x%02x", err.Command)
}

func validateHIDCommand(command byte) error {
	if command == 0 || command&0x80 != 0 {
		return &InvalidHIDCommandError{Command: command}
	}
	switch command {
	case 0x06, 0x11, 0x3b, 0x3f: // INIT, CANCEL, KEEPALIVE, ERROR.
		return &InvalidHIDCommandError{Command: command}
	}
	return nil
}
