package ctap2

import "fmt"

// Error reports a CTAP2 status-code failure.
type Error struct {
	Code    uint8
	Message string
}

// Error returns the CTAP2 error message.
func (err *Error) Error() string {
	message := err.Message
	if message == "" {
		message = statusText(err.Code)
	}
	return fmt.Sprintf("ctap2: status 0x%02x: %s", err.Code, message)
}

func statusText(code uint8) string {
	switch code {
	case 0x00:
		return "success"
	case 0x01:
		return "invalid command"
	case 0x02:
		return "invalid parameter"
	case 0x03:
		return "invalid length"
	case 0x10:
		return "CBOR parsing error"
	case 0x11:
		return "CBOR unexpected type"
	default:
		return "unknown status"
	}
}
