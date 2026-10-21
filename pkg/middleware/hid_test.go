package middleware_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
)

func TestChainHIDPreservesOrderCommandContextAndError(t *testing.T) {
	t.Parallel()
	var order []string
	failure := errors.New("device failure")
	ctx := context.WithValue(context.Background(), struct{}{}, "marker")
	base := func(got context.Context, command byte, payload []byte) ([]byte, error) {
		order = append(order, "device")
		if got != ctx || command != 0x42 || !reflect.DeepEqual(payload, []byte{0}) {
			t.Fatal("middleware changed the request")
		}
		return []byte{0xaa}, failure
	}
	wrap := func(name string) middleware.HIDFunc {
		return func(next middleware.HIDExchangeFunc) middleware.HIDExchangeFunc {
			return func(ctx context.Context, command byte, payload []byte) ([]byte, error) {
				order = append(order, name+" before")
				response, err := next(ctx, command, payload)
				order = append(order, name+" after")
				return response, err
			}
		}
	}
	response, err := middleware.ChainHID(base, wrap("first"), wrap("second"))(ctx, 0x42, []byte{0})
	want := []string{"first before", "second before", "device", "second after", "first after"}
	if !errors.Is(err, failure) || !reflect.DeepEqual(response, []byte{0xaa}) || !reflect.DeepEqual(order, want) {
		t.Fatalf("chain = %x, %v, %v", response, err, order)
	}
}
