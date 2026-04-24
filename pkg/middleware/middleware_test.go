package middleware_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
)

func TestChainPreservesMiddlewareOrder(t *testing.T) {
	t.Parallel()

	order := []string{}
	base := func(ctx context.Context, req []byte) ([]byte, error) {
		order = append(order, "base")
		return append([]byte(nil), req...), ctx.Err()
	}

	first := middleware.Func(func(next middleware.ExchangeFunc) middleware.ExchangeFunc {
		return func(ctx context.Context, req []byte) ([]byte, error) {
			order = append(order, "first-before")
			resp, err := next(ctx, req)
			order = append(order, "first-after")
			return resp, err
		}
	})
	second := middleware.Func(func(next middleware.ExchangeFunc) middleware.ExchangeFunc {
		return func(ctx context.Context, req []byte) ([]byte, error) {
			order = append(order, "second-before")
			resp, err := next(ctx, req)
			order = append(order, "second-after")
			return resp, err
		}
	})

	wrapped := middleware.Chain(base, first, second)
	if _, err := wrapped(context.Background(), []byte{0x01}); err != nil {
		t.Fatalf("wrapped exchange: %v", err)
	}

	want := []string{"first-before", "second-before", "base", "second-after", "first-after"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %#v, want %#v", order, want)
	}
}
