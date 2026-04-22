package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// Client is the public FIDO SDK facade.
type Client interface {
	Device() transport.DeviceDescriptor
	GetCapabilities(ctx context.Context) (*DeviceCapabilities, error)
	InvokeRaw(ctx context.Context, family protocol.Family, command byte, payload []byte) ([]byte, error)
	Close() error
}

// RawInvoker handles raw command invocation for one protocol family.
type RawInvoker interface {
	Protocol() protocol.Family
	InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error)
}

// Option mutates the client configuration during construction.
type Option func(*config) error

type config struct {
	middlewares []middleware.Middleware
	invokers    map[protocol.Family]RawInvoker
}

type client struct {
	session  transport.Session
	exchange middleware.ExchangeFunc
	invokers map[protocol.Family]RawInvoker
	caps     *DeviceCapabilities
}

// New creates a client facade over the supplied transport session.
func New(session transport.Session, options ...Option) (Client, error) {
	if session == nil {
		return nil, ErrSessionRequired
	}

	cfg := config{invokers: map[protocol.Family]RawInvoker{}}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}

	baseExchange := middleware.ExchangeFunc(func(ctx context.Context, req []byte) ([]byte, error) {
		return session.Exchange(ctx, req)
	})

	registeredInvokers := make(map[protocol.Family]RawInvoker, len(cfg.invokers))
	for family, invoker := range cfg.invokers {
		registeredInvokers[family] = invoker
	}

	return &client{
		session:  session,
		exchange: middleware.Chain(baseExchange, cfg.middlewares...),
		invokers: registeredInvokers,
	}, nil
}

// Device returns the descriptor for the underlying authenticator session.
func (client *client) Device() transport.DeviceDescriptor {
	return client.session.Device()
}

// InvokeRaw dispatches a raw protocol request through the configured invoker.
func (client *client) InvokeRaw(ctx context.Context, family protocol.Family, command byte, payload []byte) ([]byte, error) {
	if err := family.Validate(); err != nil {
		return nil, err
	}

	invoker, ok := client.invokers[family]
	if !ok {
		return nil, &UnsupportedProtocolError{Family: family}
	}

	return invoker.InvokeRaw(ctx, client.exchange, command, payload)
}

// Close releases the underlying transport session.
func (client *client) Close() error {
	return client.session.Close()
}
