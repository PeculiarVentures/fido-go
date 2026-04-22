package ctap1

import "fmt"

const successStatusWord uint16 = 0x9000

// Error reports a CTAP1 status-word failure.
type Error struct {
	StatusWord uint16
	Message    string
}

// Error returns the CTAP1 error message.
func (err *Error) Error() string {
	message := err.Message
	if message == "" {
		message = statusText(err.StatusWord)
	}
	return fmt.Sprintf("ctap1: status 0x%04x: %s", err.StatusWord, message)
}

func statusText(statusWord uint16) string {
	switch statusWord {
	case 0x6985:
		return "conditions not satisfied"
	case 0x6a80:
		return "invalid request data"
	case 0x6a82:
		return "file not found"
	case successStatusWord:
		return "success"
	default:
		return "unknown status"
	}
}
