package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// Locator discovers devices and opens client sessions without exposing transport internals to callers.
type Locator interface {
	List(ctx context.Context) ([]Device, error)
	Open(ctx context.Context, deviceID string, options ...Option) (Client, error)
}

type transportLocator struct {
	registry *transport.Registry
}

// NewTransportLocator creates a client-facing locator on top of registered transport backends.
func NewTransportLocator(backends ...transport.Backend) (Locator, error) {
	registry, err := transport.NewRegistry(backends...)
	if err != nil {
		return nil, err
	}
	return &transportLocator{registry: registry}, nil
}

// List returns descriptors discovered through the registered transport backends.
func (locator *transportLocator) List(ctx context.Context) ([]Device, error) {
	devices, err := locator.registry.Discover(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Device, len(devices))
	copy(result, devices)
	return result, nil
}

// Open finds a device by identifier, opens its transport session, and wraps it in a client facade.
func (locator *transportLocator) Open(ctx context.Context, deviceID string, options ...Option) (Client, error) {
	devices, err := locator.registry.Discover(ctx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, &DeviceNotFoundError{DeviceID: deviceID}
	}
	if deviceID == "" {
		deviceID = devices[0].ID
	}
	for _, device := range devices {
		if device.ID != deviceID {
			continue
		}
		session, err := locator.registry.Open(ctx, device)
		if err != nil {
			return nil, err
		}
		client, err := New(session, options...)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		return client, nil
	}

	return nil, &DeviceNotFoundError{DeviceID: deviceID}
}
