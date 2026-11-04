package usb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

// Device returns metadata of the actual opened endpoint.
func (session *hidSession) Device() transport.DeviceDescriptor { return session.device }

// Exchange sends one CTAP request and returns its complete CTAPHID response.
func (session *hidSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	return session.exchange(ctx, hidCommandForRequest(req), req)
}

// ExchangeHID exchanges a logical CTAPHID command on the initialized channel.
func (session *hidSession) ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	if err := validateHIDCommand(command); err != nil {
		return nil, transport.Wrap("exchange usb hid command", err)
	}
	return session.exchange(ctx, command|0x80, payload)
}

func (session *hidSession) exchange(ctx context.Context, command byte, payload []byte) (response []byte, resultErr error) {
	if ctx == nil {
		return nil, transport.Wrap("exchange usb hid message", hid.ErrInvalidArgument)
	}
	// Validate caller input before admission or handshake I/O. Rejection leaves
	// an otherwise healthy session usable and never sends an application packet.
	codec, err := wirehid.NewCodec(1, command, session.reportSize)
	if err != nil {
		return nil, transport.Wrap("fragment usb hid request", err)
	}
	if _, err = codec.Fragment(payload); err != nil {
		return nil, transport.Wrap("fragment usb hid request", err)
	}
	if err := session.mu.lock(ctx); err != nil {
		return nil, transport.Wrap("exchange usb hid message", err)
	}
	defer session.mu.unlock()
	if err := session.hidCallError(ctx); err != nil {
		if ctx.Err() != nil {
			session.retire()
		}
		return nil, transport.Wrap("exchange usb hid message", classifyHIDError(err))
	}
	session.progress = &exchangeProgress{stage: StageINIT, outcome: hid.OutcomeNotSubmitted}
	defer func() {
		progress := session.progress
		session.progress = nil
		if resultErr == nil {
			return
		}
		var deviceError *HIDError
		definitive := errors.As(resultErr, &deviceError)
		if !definitive {
			// Includes cancellation between report calls. Closing this connection
			// prevents late input from being consumed by another application exchange.
			progress.ambiguous = progress.ambiguous || progress.packets > 0
			session.retire()
		}
		resultErr = progress.wrap(classifyHIDError(resultErr))
	}()
	if err := session.ensureChannel(ctx); err != nil {
		return nil, transport.Wrap("initialize usb hid channel", err)
	}
	session.progress = &exchangeProgress{stage: StageRequest, outcome: hid.OutcomeNotSubmitted}
	return exchangeHIDMessage(ctx, session.channelID, command, session.reportSize, payload, session.writePacket, func(ctx context.Context) ([]byte, error) {
		session.progress.stage = StageResponse
		return session.readPacket(ctx)
	})
}

func (session *hidSession) ensureChannel(ctx context.Context) error {
	if session.channelID != 0 {
		return nil
	}
	return session.initializeChannel(ctx)
}

func (session *hidSession) writePacket(ctx context.Context, packet []byte) error {
	if err := session.hidCallError(ctx); err != nil {
		return err
	}
	// hid.Conn.Write waits for native completion or its own context, even when
	// the connection is retired. A device that stops accepting Output reports
	// would otherwise hold an exchange without a caller deadline forever.
	writeCtx, cancel := context.WithTimeout(ctx, hidWriteTimeout)
	defer cancel()
	result, err := session.conn.Write(writeCtx, hid.Report{ID: session.layout.Output.ID, Data: packet})
	if err != nil && ctx.Err() == nil && writeCtx.Err() != nil {
		// Report a local write deadline as a timeout, not as the caller's context.
		err = fmt.Errorf("transport/usb: HID report write exceeded %s: %w", hidWriteTimeout, errors.Join(hid.ErrTimeout, err))
	}
	if session.progress != nil {
		session.progress.outcome = result.Outcome
		if result.Outcome == hid.OutcomeCompleted {
			session.progress.packets++
		}
		if result.Outcome == hid.OutcomeUnknown {
			session.progress.ambiguous = true
		}
	}
	if err == nil && result.Outcome != hid.OutcomeCompleted {
		err = hid.ErrIO
	}
	return err
}

func (session *hidSession) readPacket(ctx context.Context) ([]byte, error) {
	return session.readPacketWithTimeout(ctx, 0)
}

func (session *hidSession) readPacketWithTimeout(ctx context.Context, wait time.Duration) ([]byte, error) {
	if err := session.hidCallError(ctx); err != nil {
		return nil, err
	}
	report, err := session.conn.Read(ctx, wait)
	if err != nil {
		return nil, err
	}
	if report.ID != session.layout.Input.ID || len(report.Data) != session.reportSize {
		return nil, hid.ErrInvalidReport
	}
	return report.Data, nil
}

func hidCommandForRequest(req []byte) byte {
	if isCTAP1APDU(req) {
		return hidCommandMsg
	}
	return hidCommandCBOR
}

func isCTAP1APDU(req []byte) bool {
	if len(req) < 4 || req[0] != 0 {
		return false
	}
	switch req[1] {
	case 1, 2, 3:
		return true
	default:
		return false
	}
}

var _ HIDSession = (*hidSession)(nil)
