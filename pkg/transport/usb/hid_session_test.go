package usb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

const testChannelID uint32 = 0x01020304

// fakeHIDDevice implements the public HID boundary for protocol tests.
type fakeHIDDevice struct {
	mu          sync.Mutex
	writes      [][]byte
	reads       chan []byte
	readStarted chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
	onWrite     func([]byte) error
	closeCalls  int
	closeErr    error
}

func newFakeHIDDevice() *fakeHIDDevice {
	return &fakeHIDDevice{reads: make(chan []byte, 256), readStarted: make(chan struct{}, 256), closed: make(chan struct{})}
}
func (dev *fakeHIDDevice) Endpoint() hid.Endpoint { return hid.Endpoint{ID: "fake"} }
func (dev *fakeHIDDevice) Layout() hid.ReportLayout {
	return hid.ReportLayout{Input: hid.ReportSpec{Size: hidReportSize}, Output: hid.ReportSpec{Size: hidReportSize}}
}
func (dev *fakeHIDDevice) Write(ctx context.Context, report hid.Report) (hid.WriteResult, error) {
	if err := ctx.Err(); err != nil {
		return hid.WriteResult{Outcome: hid.OutcomeNotSubmitted}, err
	}
	dev.mu.Lock()
	dev.writes = append(dev.writes, append([]byte(nil), report.Data...))
	dev.mu.Unlock()
	if report.ID != 0 || len(report.Data) != hidReportSize {
		return hid.WriteResult{Outcome: hid.OutcomeNotSubmitted}, hid.ErrInvalidReport
	}
	if dev.onWrite != nil {
		done := make(chan error, 1)
		go func() { done <- dev.onWrite(report.Data) }()
		select {
		case err := <-done:
			if err != nil {
				return hid.WriteResult{Outcome: hid.OutcomeUnknown}, err
			}
		case <-ctx.Done():
			return hid.WriteResult{Outcome: hid.OutcomeUnknown}, ctx.Err()
		}
	}
	return hid.WriteResult{Outcome: hid.OutcomeCompleted}, nil
}
func (dev *fakeHIDDevice) Read(ctx context.Context, wait time.Duration) (hid.Report, error) {
	dev.readStarted <- struct{}{}
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case packet := <-dev.reads:
		return hid.Report{Data: packet}, nil
	case <-dev.closed:
		return hid.Report{}, hid.ErrClosed
	case <-ctx.Done():
		return hid.Report{}, ctx.Err()
	case <-timeout:
		return hid.Report{}, hid.ErrTimeout
	}
}
func (dev *fakeHIDDevice) Close(context.Context) error {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	dev.closeOnce.Do(func() { dev.closeCalls++; close(dev.closed) })
	return dev.closeErr
}
func (dev *fakeHIDDevice) writtenPackets() [][]byte {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	packets := make([][]byte, len(dev.writes))
	for i, p := range dev.writes {
		packets[i] = append([]byte(nil), p...)
	}
	return packets
}

func framedHIDPayload(t *testing.T, channel uint32, command byte, payload []byte) [][]byte {
	t.Helper()
	codec, err := wirehid.NewCodec(channel, command, hidReportSize)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := codec.Fragment(payload)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

func queueHIDPayload(t *testing.T, dev *fakeHIDDevice, command byte, payload []byte) {
	t.Helper()
	for _, packet := range framedHIDPayload(t, testChannelID, command, payload) {
		dev.reads <- packet
	}
}

func newTestHIDSession(t *testing.T) (*hidSession, *fakeHIDDevice) {
	t.Helper()
	dev := newFakeHIDDevice()
	session := &hidSession{conn: dev, layout: dev.Layout(), channelID: testChannelID, reportSize: hidReportSize}
	t.Cleanup(func() {
		_ = session.Close()
		dev.mu.Lock()
		defer dev.mu.Unlock()
		if dev.closeCalls != 1 {
			t.Errorf("close calls = %d", dev.closeCalls)
		}
	})
	return session, dev
}

func TestHIDSessionExplicitCommandFragmentsAndReassemblesUnchangedPayloads(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	request := append([]byte{0x00, 0x03, 0x00, 0x00}, bytes.Repeat([]byte{0x42}, 150)...)
	response := append([]byte{0x6a, 0x80}, bytes.Repeat([]byte{0xab}, 180)...)
	queueHIDPayload(t, dev, hidCommandKeepalive, []byte{0x01})
	queueHIDPayload(t, dev, 0xc2, response)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := session.ExchangeHID(ctx, 0x42, request)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("ExchangeHID = %x, %v", got, err)
	}
	written, want := dev.writtenPackets(), framedHIDPayload(t, testChannelID, 0xc2, request)
	if len(written) != len(want) {
		t.Fatalf("packet count = %d, want %d", len(written), len(want))
	}
	for i := range want {
		if !bytes.Equal(written[i], want[i]) {
			t.Fatalf("packet %d = %x, want %x", i, written[i], want[i])
		}
	}
}

func TestHIDSessionInitializesOnceAndReusesChannelForCTAPAndVendorCommands(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	session.channelID = 0
	dev.onWrite = func(packet []byte) error {
		channel := binary.BigEndian.Uint32(packet[:4])
		command := packet[4]
		var response []byte
		if command == hidCommandInit {
			if channel != hidBroadcastCID {
				return errors.New("INIT did not use broadcast channel")
			}
			response = append([]byte(nil), packet[7:15]...)
			response = binary.BigEndian.AppendUint32(response, testChannelID)
			response = append(response, 2, 5, 4, 3, 4)
		} else {
			if channel != testChannelID {
				return fmt.Errorf("unexpected channel %08x", channel)
			}
			if command != hidCommandPing {
				response = []byte{0xaa}
			}
		}
		codec, err := wirehid.NewCodec(channel, command, hidReportSize)
		if err != nil {
			return err
		}
		packets, err := codec.Fragment(response)
		if err != nil {
			return err
		}
		for _, reply := range packets {
			dev.reads <- reply
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := []func() ([]byte, error){
		func() ([]byte, error) { return session.ExchangeHID(ctx, 0x42, []byte{0}) },
		func() ([]byte, error) { return session.Exchange(ctx, []byte{0, 3, 0, 0, 0}) },
		func() ([]byte, error) { return session.Exchange(ctx, []byte{0x04}) },
		func() ([]byte, error) { return session.Exchange(ctx, []byte{0x42, 0xa0}) },
		func() ([]byte, error) { return session.ExchangeHID(ctx, 0x42, []byte{1}) },
	}
	for _, call := range calls {
		if got, err := call(); err != nil || !bytes.Equal(got, []byte{0xaa}) {
			t.Fatalf("exchange = %x, %v", got, err)
		}
	}
	packets := dev.writtenPackets()
	want := []byte{hidCommandInit, hidCommandPing, 0xc2, hidCommandMsg, hidCommandCBOR, hidCommandCBOR, 0xc2}
	if len(packets) != len(want) {
		t.Fatalf("packet count = %d, want %d", len(packets), len(want))
	}
	for i, command := range want {
		if packets[i][4] != command {
			t.Fatalf("packet %d command = %02x, want %02x", i, packets[i][4], command)
		}
	}
	if !bytes.Equal(packets[3][7:12], []byte{0, 3, 0, 0, 0}) || !bytes.Equal(packets[5][7:9], []byte{0x42, 0xa0}) {
		t.Fatal("ordinary CTAP payloads changed")
	}
}

func TestHIDSessionRejectsInvalidCommandsBeforeDeviceAccess(t *testing.T) {
	t.Parallel()
	for _, command := range []byte{0, 0x06, 0x11, 0x3b, 0x3f, 0x80, 0xc2, 0xff} {
		session := &hidSession{}
		_, err := session.ExchangeHID(context.Background(), command, nil)
		var invalid *InvalidHIDCommandError
		var wrapped *transport.Error
		if !errors.As(err, &invalid) || invalid.Command != command || !errors.As(err, &wrapped) {
			t.Fatalf("command %02x error = %v", command, err)
		}
	}
	for _, command := range []byte{0x01, 0x03, 0x04, 0x08, 0x10, 0x40, 0x7f} {
		session, dev := newTestHIDSession(t)
		queueHIDPayload(t, dev, command|0x80, nil)
		if payload, err := session.ExchangeHID(context.Background(), command, nil); err != nil || len(payload) != 0 {
			t.Fatalf("valid command %02x = %x, %v", command, payload, err)
		}
	}
}

func TestHIDSessionRejectsMalformedVendorResponses(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"command", "sequence", "short", "error length"} {
		t.Run(kind, func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			packets := framedHIDPayload(t, testChannelID, 0xc2, bytes.Repeat([]byte{0xaa}, 100))
			switch kind {
			case "command":
				packets[0][4] = hidCommandCBOR
			case "sequence":
				packets[1][4] = 3
			case "short":
				packets[0] = packets[0][:5]
			case "error length":
				packets = framedHIDPayload(t, testChannelID, hidCommandError, []byte{1, 2})
			}
			for _, packet := range packets {
				dev.reads <- packet
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			payload, err := session.ExchangeHID(ctx, 0x42, nil)
			var wrapped *transport.Error
			if err == nil || payload != nil || !errors.As(err, &wrapped) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("malformed response = %x, %v", payload, err)
			}
		})
	}
}

func TestHIDSessionPreservesHIDAndIOErrors(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	queueHIDPayload(t, dev, hidCommandError, []byte{0x01})
	_, err := session.ExchangeHID(context.Background(), 0x42, nil)
	var hidError *HIDError
	if !errors.As(err, &hidError) || hidError.Code != 0x01 {
		t.Fatalf("error = %v, want HIDError(INVALID_CMD)", err)
	}
	session, dev = newTestHIDSession(t)
	dev.onWrite = func([]byte) error { return os.ErrPermission }
	if _, err := session.ExchangeHID(context.Background(), 0x42, nil); !errors.Is(err, transport.ErrPermissionDenied) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("write error = %v", err)
	}
	session, dev = newTestHIDSession(t)
	if _, err := session.ExchangeHID(context.Background(), 0x42, make([]byte, 7610)); !errors.Is(err, wirehid.ErrPayloadTooLarge) {
		t.Fatalf("oversized payload error = %v", err)
	}
	if len(dev.writtenPackets()) != 0 {
		t.Fatal("oversized request wrote packets")
	}
}

func TestHIDSessionRejectsInvalidInitialization(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"short", "nonce"} {
		t.Run(kind, func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			session.channelID = 0
			payload := make([]byte, 17)
			if kind == "short" {
				payload = payload[:8]
			}
			for _, packet := range framedHIDPayload(t, hidBroadcastCID, hidCommandInit, payload) {
				dev.reads <- packet
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := session.ExchangeHID(ctx, 0x42, nil)
			if kind == "nonce" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("unrelated nonce error = %v, want deadline", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), kind) {
				t.Fatalf("init error = %v, want %s", err, kind)
			}
			if packets := dev.writtenPackets(); len(packets) != 1 || packets[0][4] != hidCommandInit {
				t.Fatal("vendor request sent after invalid initialization")
			}
		})
	}
}
