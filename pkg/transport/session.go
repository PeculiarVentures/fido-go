package transport

import "context"

// Session performs one complete raw request-response exchange with an
// authenticator over a specific transport.
//
// Implementations must be safe for concurrent Exchange calls. Backends that
// depend on single-threaded transport state must serialize internally.
type Session interface {
	Device() DeviceDescriptor
	Exchange(ctx context.Context, req []byte) ([]byte, error)
	Close() error
}
