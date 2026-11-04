//go:build hid_diagnostics

package power

import "fmt"

// Kind identifies a safe, transport-independent diagnostic error category.
type Kind uint8

const (
	KindIO Kind = iota
	KindClosed
	KindRemoved
	KindPermission
	KindBusy
	KindUnsupported
	KindInvalidArgument
	KindResourceLimit
)

// Error retains native details without device addresses or transport dependencies.
type Error struct {
	Op      string
	Kind    Kind
	Domain  string
	Code    uint64
	Message string
	Cause   error
}

// Error returns text without transport addresses or device metadata.
func (e *Error) Error() string {
	if e.Domain != "" {
		return fmt.Sprintf("power diagnostics: %s: %s 0x%x: %s", e.Op, e.Domain, e.Code, e.Message)
	}
	return "power diagnostics: " + e.Op + ": " + e.Message
}

// Unwrap preserves the original cause, including context cancellation.
func (e *Error) Unwrap() error { return e.Cause }

func failure(op string, kind Kind, message string) error {
	return &Error{Op: op, Kind: kind, Message: message}
}
