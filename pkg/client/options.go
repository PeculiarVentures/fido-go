package client

import (
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// WithMiddleware appends one middleware to the client exchange chain.
func WithMiddleware(wrapper middleware.Middleware) Option {
	return func(cfg *config) error {
		if wrapper == nil {
			return ErrMiddlewareRequired
		}
		cfg.middlewares = append(cfg.middlewares, wrapper)
		return nil
	}
}

// WithRawInvoker registers one protocol-specific raw invoker.
func WithRawInvoker(invoker RawInvoker) Option {
	return func(cfg *config) error {
		if invoker == nil {
			return ErrRawInvokerRequired
		}

		family := invoker.Protocol()
		if err := family.Validate(); err != nil {
			return err
		}

		if _, exists := cfg.invokers[family]; exists {
			return &DuplicateRawInvokerError{Family: family}
		}

		cfg.invokers[family] = invoker
		return nil
	}
}

// WithInteraction registers one interaction handler for user-presence and PIN prompts.
func WithInteraction(handler InteractionHandler) Option {
	return func(cfg *config) error {
		if handler == nil {
			return ErrInteractionHandlerRequired
		}
		cfg.interaction = handler
		return nil
	}
}

// Supported reports whether the client configuration includes a raw invoker for the family.
func Supported(candidate Client, family protocol.Family) bool {
	concrete, ok := candidate.(*client)
	if !ok {
		return false
	}
	_, ok = concrete.invokers[family]
	return ok
}
