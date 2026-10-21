package middleware

import "context"

// HIDExchangeFunc exchanges one complete payload with a logical CTAPHID command.
type HIDExchangeFunc func(ctx context.Context, command byte, payload []byte) ([]byte, error)

// HIDMiddleware wraps explicit CTAPHID exchanges independently of CTAP exchanges.
type HIDMiddleware interface {
	WrapHIDExchange(next HIDExchangeFunc) HIDExchangeFunc
}

// HIDFunc adapts a function to the HIDMiddleware interface.
type HIDFunc func(next HIDExchangeFunc) HIDExchangeFunc

// WrapHIDExchange applies the functional middleware adapter.
func (fn HIDFunc) WrapHIDExchange(next HIDExchangeFunc) HIDExchangeFunc {
	return fn(next)
}

// ChainHID applies HID middleware in registration order.
func ChainHID(base HIDExchangeFunc, middlewares ...HIDMiddleware) HIDExchangeFunc {
	wrapped := base
	for index := len(middlewares) - 1; index >= 0; index-- {
		wrapped = middlewares[index].WrapHIDExchange(wrapped)
	}
	return wrapped
}
