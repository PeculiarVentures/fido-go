package usb

import (
	"context"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

// exchangeMutex lets a queued exchange honor cancellation without interrupting
// another caller's active transaction. Its zero value is ready for use.
type exchangeMutex struct {
	once sync.Once
	busy chan struct{}
}

func (mutex *exchangeMutex) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	mutex.once.Do(func() { mutex.busy = make(chan struct{}, 1) })
	select {
	case mutex.busy <- struct{}{}:
		if err := ctx.Err(); err != nil {
			mutex.unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (mutex *exchangeMutex) unlock() {
	<-mutex.busy
}

func exchangeHIDMessage(ctx context.Context, channelID uint32, command byte, reportSize int, payload []byte,
	writePacket func(context.Context, []byte) error, readPacket func(context.Context) ([]byte, error),
) ([]byte, error) {
	codec, err := wirehid.NewCodec(channelID, command, reportSize)
	if err != nil {
		return nil, transport.Wrap("fragment usb hid request", classifyHIDError(err))
	}
	packets, err := codec.Fragment(payload)
	if err != nil {
		return nil, transport.Wrap("fragment usb hid request", classifyHIDError(err))
	}
	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return nil, transport.Wrap("write usb hid packet", err)
		}
		if err := writePacket(ctx, packet); err != nil {
			return nil, transport.Wrap("write usb hid packet", classifyHIDError(err))
		}
	}
	response, err := readHIDMessage(ctx, reportSize, channelID, command, readPacket)
	if err != nil {
		return nil, transport.Wrap("read usb hid response", classifyHIDError(err))
	}
	return response, nil
}
