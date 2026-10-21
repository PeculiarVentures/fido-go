package usb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
	hid "github.com/sstallion/go-hid"
)

const (
	hidCommandPing        = 0x81
	hidErrorChannelBusy   = 0x06
	hidInitTimeout        = 3 * time.Second
	hidInitResponseWait   = 300 * time.Millisecond
	hidInitBusyRetries    = 20
	hidInitBusyRetryDelay = 50 * time.Millisecond
)

func (session *hidSession) initializeChannel(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, hidInitTimeout)
	defer cancel()
	var channelID uint32
	_, err := retryHIDHandshake(ctx, func() ([]byte, error) {
		nonce := make([]byte, 8)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		response, err := session.exchangeInit(ctx, nonce)
		if err != nil {
			return nil, err
		}
		channelID = binary.BigEndian.Uint32(response[8:12])
		if channelID == 0 || channelID == hidBroadcastCID {
			return nil, fmt.Errorf("transport/usb: invalid allocated channel %08x", channelID)
		}
		// INIT can succeed while an old transaction is still finishing. Probe
		// readiness without ever replaying the caller's application request.
		// Retry the whole handshake on a fresh CID: a late PING reply must not
		// remain on the channel eventually used by application exchanges.
		response, err = exchangeHIDMessage(ctx, channelID, hidCommandPing, session.reportSize, nil, session.writePacket, session.readInitPacket)
		if err != nil {
			return nil, err
		}
		if len(response) != 0 {
			return nil, fmt.Errorf("transport/usb: invalid initialization PING echo")
		}
		return nil, nil
	})
	if err == nil {
		session.channelID = channelID
	}
	return err
}

func (session *hidSession) exchangeInit(ctx context.Context, nonce []byte) ([]byte, error) {
	codec, err := wirehid.NewCodec(hidBroadcastCID, hidCommandInit, session.reportSize)
	if err != nil {
		return nil, err
	}
	packets, err := codec.Fragment(nonce)
	if err != nil {
		return nil, err
	}
	for _, packet := range packets {
		if err := session.writePacket(ctx, packet); err != nil {
			return nil, err
		}
	}
	for {
		response, err := readHIDMessage(ctx, session.reportSize, hidBroadcastCID, hidCommandInit, session.readInitPacket)
		if err != nil {
			return nil, err
		}
		if len(response) < 17 {
			return nil, fmt.Errorf("transport/usb: init response is too short")
		}
		// Broadcast responses can belong to a previous open or another client.
		if bytes.Equal(response[:8], nonce) {
			return response, nil
		}
	}
}

func (session *hidSession) readInitPacket(ctx context.Context) ([]byte, error) {
	return session.readPacketWithTimeout(ctx, hidInitResponseWait)
}

// retryHIDHandshake is used only by INIT and the readiness PING. A device may
// reject or drop a handshake while an old transaction finishes. These harmless
// commands can be replayed; application commands are always sent once.
func retryHIDHandshake(ctx context.Context, exchange func() ([]byte, error)) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := exchange()
		var hidErr *HIDError
		retry := errors.Is(err, hid.ErrTimeout) || (errors.As(err, &hidErr) && hidErr.Code == hidErrorChannelBusy)
		if !retry || attempt == hidInitBusyRetries {
			return response, err
		}
		timer := time.NewTimer(hidInitBusyRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func hidChannelReader(reportSize int, channelID uint32, readPacket func(context.Context) ([]byte, error)) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			packet, err := readPacket(ctx)
			if err != nil {
				return nil, err
			}
			if len(packet) == reportSize && binary.BigEndian.Uint32(packet[:4]) != channelID {
				continue
			}
			return packet, nil
		}
	}
}
