package client

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

var (
	// ErrSessionRequired reports that client construction requires a transport session.
	ErrSessionRequired = errors.New("client: session is required")
	// ErrRawInvokerRequired reports that raw invoker options cannot be nil.
	ErrRawInvokerRequired = errors.New("client: raw invoker is required")
	// ErrMiddlewareRequired reports that middleware options cannot be nil.
	ErrMiddlewareRequired = errors.New("client: middleware is required")
	// ErrTraceRecorderRequired reports that tracing options cannot be nil.
	ErrTraceRecorderRequired = errors.New("client: trace recorder is required")
	// ErrPINRequired reports that the requested flow requires a PIN value.
	ErrPINRequired = errors.New("client: pin is required")
	// ErrNewPINRequired reports that the requested flow requires a replacement PIN value.
	ErrNewPINRequired = errors.New("client: new pin is required")
	// ErrNoCapableProtocol reports that no registered protocol probe succeeded.
	ErrNoCapableProtocol = errors.New("client: no capable protocol detected")
)

// UnsupportedProtocolError reports that the client has no raw invoker for the requested protocol.
type UnsupportedProtocolError struct {
	Family protocol.Family
}

// Error returns the unsupported protocol message.
func (err *UnsupportedProtocolError) Error() string {
	return fmt.Sprintf("client: protocol %q is not configured", err.Family)
}

// DuplicateRawInvokerError reports an attempt to register multiple invokers for the same protocol.
type DuplicateRawInvokerError struct {
	Family protocol.Family
}

// Error returns the duplicate invoker message.
func (err *DuplicateRawInvokerError) Error() string {
	return fmt.Sprintf("client: protocol %q already has a raw invoker", err.Family)
}

// DeviceNotFoundError reports that the requested device could not be resolved.
type DeviceNotFoundError struct {
	DeviceID string
}

// Error returns the missing-device message.
func (err *DeviceNotFoundError) Error() string {
	return fmt.Sprintf("client: device %q was not found", err.DeviceID)
}
