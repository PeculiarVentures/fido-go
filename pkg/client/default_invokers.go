package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// WithDefaultRawInvokers registers the built-in CTAP1 and CTAP2 raw invokers.
func WithDefaultRawInvokers() Option {
	return func(cfg *config) error {
		for _, invoker := range []RawInvoker{ctap1RawInvoker{}, ctap2RawInvoker{}} {
			if err := WithRawInvoker(invoker)(cfg); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithDefaultCTAP2RawInvoker registers only the built-in CTAP2 raw invoker.
func WithDefaultCTAP2RawInvoker() Option {
	return WithRawInvoker(ctap2RawInvoker{})
}

type ctap1RawInvoker struct{}

func (invoker ctap1RawInvoker) Protocol() protocol.Family {
	return protocol.FamilyCTAP1
}

func (invoker ctap1RawInvoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	var (
		request []byte
		err     error
	)
	if command == ctap1.CommandVersion && len(payload) == 0 {
		request, err = ctap1.EncodeShortAPDU(command, nil)
	} else {
		request, err = ctap1.EncodeRawAPDU(command, payload)
	}
	if err != nil {
		return nil, err
	}
	return exchange(ctx, request)
}

type ctap2RawInvoker struct{}

func (invoker ctap2RawInvoker) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

func (invoker ctap2RawInvoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	request := append([]byte{command}, payload...)
	return exchange(ctx, request)
}
