package transport

import "fmt"

// Error wraps transport-layer failures with the operation name that failed.
type Error struct {
	Op  string
	Err error
}

// Error returns the transport-layer error message.
func (err *Error) Error() string {
	if err == nil {
		return "transport: <nil>"
	}
	if err.Op == "" {
		return fmt.Sprintf("transport: %v", err.Err)
	}
	return fmt.Sprintf("transport: %s: %v", err.Op, err.Err)
}

// Unwrap exposes the wrapped low-level error.
func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}
