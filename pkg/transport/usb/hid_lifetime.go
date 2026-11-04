package usb

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

const hidCloseTimeout = 250 * time.Millisecond

// hidWriteTimeout bounds one Output report. CTAPHID reports are 64 bytes, so a
// healthy device accepts one well within this interval. Tests may shorten it.
var hidWriteTimeout = 5 * time.Second

type hidSession struct {
	mu         exchangeMutex
	closing    atomic.Bool
	device     transport.DeviceDescriptor
	conn       hid.Conn
	layout     hid.ReportLayout
	channelID  uint32
	reportSize int
	progress   *exchangeProgress // protected by the exchange mutex
}

// Close retires the session and waits up to 250 ms for native cleanup.
func (session *hidSession) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), hidCloseTimeout)
	defer cancel()
	return session.CloseContext(ctx)
}

// CloseContext immediately revokes new exchanges and waits for the HID
// supervisor's shared cleanup. An expired context never abandons ownership.
func (session *hidSession) CloseContext(ctx context.Context) error {
	session.closing.Store(true)
	if ctx == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = session.conn.Close(ctx)
		return transport.Wrap("close usb hid session", hid.ErrInvalidArgument)
	}
	return transport.Wrap("close usb hid session", classifyHIDError(session.conn.Close(ctx)))
}

func (session *hidSession) retire() {
	session.closing.Store(true)
	// Conn.Close initiates retirement even for an already canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = session.conn.Close(ctx)
}

func (session *hidSession) hidCallError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.closing.Load() {
		return hid.ErrClosed
	}
	return nil
}

var _ transport.ContextCloser = (*hidSession)(nil)
