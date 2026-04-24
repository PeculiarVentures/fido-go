package transport

import (
	"errors"
	"fmt"
	"os"
)

var (
	// ErrDisconnected marks transport failures caused by a detached or unavailable device.
	ErrDisconnected = errors.New("transport disconnected")
	// ErrPermissionDenied marks transport failures caused by missing OS or device permissions.
	ErrPermissionDenied = errors.New("transport permission denied")
	// ErrTemporary marks transport failures that may succeed when retried.
	ErrTemporary = errors.New("transport temporary failure")
	// ErrUnsupported marks transport failures caused by unsupported backends or transport kinds.
	ErrUnsupported = errors.New("transport unsupported")
)

// Error wraps transport-layer failures with the operation name that failed.
type Error struct {
	Op  string
	Err error
}

// Wrap annotates a transport failure with the transport operation that failed.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Err: err}
}

// Disconnected annotates an error as a disconnected-device transport failure.
func Disconnected(err error) error {
	return withCategory(err, ErrDisconnected)
}

// PermissionDenied annotates an error as a permission-related transport failure.
func PermissionDenied(err error) error {
	return withCategory(err, ErrPermissionDenied)
}

// Temporary annotates an error as a retryable transport failure.
func Temporary(err error) error {
	return withCategory(err, ErrTemporary)
}

// Unsupported annotates an error as an unsupported transport operation.
func Unsupported(err error) error {
	return withCategory(err, ErrUnsupported)
}

// ClassifyCommon applies generic transport categories that do not depend on one backend.
func ClassifyCommon(err error) error {
	if err == nil {
		return nil
	}
	if hasCategory(err) {
		return err
	}
	if os.IsPermission(err) {
		return PermissionDenied(err)
	}
	var temporary interface{ Temporary() bool }
	if errors.As(err, &temporary) && temporary.Temporary() {
		return Temporary(err)
	}
	return err
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

func withCategory(err error, category error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, category) {
		return err
	}
	return fmt.Errorf("%w: %w", category, err)
}

func hasCategory(err error) bool {
	return errors.Is(err, ErrDisconnected) ||
		errors.Is(err, ErrPermissionDenied) ||
		errors.Is(err, ErrTemporary) ||
		errors.Is(err, ErrUnsupported)
}
