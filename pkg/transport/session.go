package transport

import "context"

// Session performs one complete raw request-response exchange with an
// authenticator over a specific transport.
type Session interface {
	Device() DeviceDescriptor
	Exchange(ctx context.Context, req []byte) ([]byte, error)
	Close() error
}
