package client

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// HIDClient optionally extends Client with explicit CTAPHID message exchange.
// Implementing this interface does not imply support on every underlying session.
type HIDClient interface {
	Client
	ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error)
}

// ExchangeHID sends a logical CTAPHID command through an optional HIDClient.
// Use 0x42 rather than the encoded packet byte 0xc2. Payload and response bytes
// are exchanged unchanged, without APDU/CBOR wrapping or CTAP status decoding.
// Unsupported clients or sessions return a transport.ErrUnsupported error.
func ExchangeHID(ctx context.Context, sdk Client, command byte, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, transport.Wrap("exchange hid", err)
	}
	if candidate, ok := sdk.(HIDClient); ok {
		return candidate.ExchangeHID(ctx, command, payload)
	}
	return nil, unsupportedHIDExchange()
}

// ExchangeHID exchanges a complete CTAPHID message on the existing session.
// It needs neither a raw invoker nor a CTAP2 capability probe. INIT/CANCEL are
// session-owned; cancel through ctx. Cancellation may close the HID connection.
func (client *client) ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, transport.Wrap("exchange hid", err)
	}
	return client.hidExchange(ctx, command, payload)
}

// WithHIDMiddleware appends a wrapper to the explicit CTAPHID exchange chain.
// WithMiddleware continues to wrap only the existing CTAP exchange chain.
func WithHIDMiddleware(wrapper middleware.HIDMiddleware) Option {
	return func(cfg *config) error {
		if wrapper == nil {
			return ErrMiddlewareRequired
		}
		cfg.hidMiddlewares = append(cfg.hidMiddlewares, wrapper)
		return nil
	}
}

func unsupportedHIDExchange() error {
	return transport.Wrap("exchange hid", transport.Unsupported(errors.New("client: session does not support explicit CTAPHID exchange")))
}

var _ HIDClient = (*client)(nil)
