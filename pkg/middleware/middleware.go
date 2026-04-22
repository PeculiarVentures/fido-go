package middleware

import "context"

// ExchangeFunc performs one raw request-response exchange.
type ExchangeFunc func(ctx context.Context, req []byte) ([]byte, error)

// Middleware wraps a raw exchange function with cross-cutting behavior.
type Middleware interface {
	WrapExchange(next ExchangeFunc) ExchangeFunc
}

// Chain applies middleware in registration order.
func Chain(base ExchangeFunc, middlewares ...Middleware) ExchangeFunc {
	wrapped := base
	for index := len(middlewares) - 1; index >= 0; index-- {
		wrapped = middlewares[index].WrapExchange(wrapped)
	}
	return wrapped
}
