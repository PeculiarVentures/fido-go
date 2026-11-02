package hid

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Error categories can be inspected with errors.Is.
var (
	ErrClosed          = errors.New("hid: closed")
	ErrRemoved         = errors.New("hid: removed")
	ErrPermission      = errors.New("hid: permission denied")
	ErrBusy            = errors.New("hid: busy")
	ErrUnsupported     = errors.New("hid: unsupported")
	ErrInvalidArgument = errors.New("hid: invalid argument")
	ErrInvalidReport   = errors.New("hid: invalid report")
	ErrStaleEndpoint   = errors.New("hid: stale endpoint")
	ErrTimeout         = errors.New("hid: report wait timeout")
	ErrIO              = errors.New("hid: I/O failure")
	ErrResourceLimit   = errors.New("hid: resource limit")
)

// NativeError preserves a platform error domain, code, and diagnostic message.
type NativeError struct {
	Domain  string
	Code    uint64
	Message string
}

// Error returns the native diagnostic without inferring delivery or removal.
func (e *NativeError) Error() string {
	return fmt.Sprintf("hid: %s 0x%x: %s", e.Domain, e.Code, e.Message)
}

// Error retains operation, category, native details, and original causes.
type Error struct {
	Op       string
	Endpoint EndpointID
	Kind     error
	Native   *NativeError
	Cause    error
}

// Error returns a concise operation diagnostic.
func (e *Error) Error() string {
	detail := e.Kind
	if e.Cause != nil {
		detail = e.Cause
	} else if e.Native != nil {
		detail = e.Native
	}
	if e.Endpoint != "" {
		return fmt.Sprintf("hid: %s %q: %v", e.Op, e.Endpoint, detail)
	}
	return fmt.Sprintf("hid: %s: %v", e.Op, detail)
}

// Unwrap exposes all retained causes for errors.Is and errors.As.
func (e *Error) Unwrap() []error {
	result := make([]error, 0, 3)
	if e.Kind != nil {
		result = append(result, e.Kind)
	}
	if e.Native != nil {
		result = append(result, e.Native)
	}
	if e.Cause != nil {
		result = append(result, e.Cause)
	}
	return result
}

func operationError(op string, id EndpointID, err error) error {
	if err == nil {
		return nil
	}
	kind := ErrIO
	var native *NativeError
	var de *driver.Error
	if errors.As(err, &de) {
		kinds := [...]error{ErrIO, ErrClosed, ErrRemoved, ErrPermission, ErrBusy, ErrUnsupported, ErrInvalidArgument, ErrInvalidReport, ErrStaleEndpoint, ErrTimeout, ErrResourceLimit}
		if int(de.Kind) < len(kinds) {
			kind = kinds[de.Kind]
		}
		if de.Domain != "" {
			native = &NativeError{Domain: de.Domain, Code: de.Code, Message: de.Message}
		}
	} else {
		for _, candidate := range []error{ErrClosed, ErrRemoved, ErrPermission, ErrBusy, ErrUnsupported, ErrInvalidArgument, ErrInvalidReport, ErrStaleEndpoint, ErrTimeout, ErrResourceLimit} {
			if errors.Is(err, candidate) {
				kind = candidate
				break
			}
		}
	}
	return &Error{Op: op, Endpoint: id, Kind: kind, Native: native, Cause: err}
}
