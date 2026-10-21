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

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
	hid "github.com/sstallion/go-hid"
)

const testChannelID uint32 = 0x01020304

// fakeHIDDevice emulates the native report API, including the output report ID.
type fakeHIDDevice struct {
	mu          sync.Mutex
	writes      [][]byte
	reads       chan []byte
	readStarted chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
	onWrite     func([]byte) error
	active      int
	closeCalls  int
	violations  int
	closeErr    error
}

func newFakeHIDDevice() *fakeHIDDevice {
	return &fakeHIDDevice{reads: make(chan []byte, 256), readStarted: make(chan struct{}, 256), closed: make(chan struct{})}
}

func (dev *fakeHIDDevice) Write(report []byte) (int, error) {
	if err := dev.beginCall(); err != nil {
		return 0, err
	}
	defer dev.endCall()
	dev.mu.Lock()
	dev.writes = append(dev.writes, append([]byte(nil), report...))
	dev.mu.Unlock()
	if len(report) != hidReportSize+1 || report[0] != 0 {
		return 0, fmt.Errorf("unexpected output report: %x", report)
	}
	if dev.onWrite != nil {
		if err := dev.onWrite(report[1:]); err != nil {
			return 0, err
		}
	}
	return len(report), nil
}

func (dev *fakeHIDDevice) ReadWithTimeout(buffer []byte, timeout time.Duration) (int, error) {
	if err := dev.beginCall(); err != nil {
		return 0, err
	}
	defer dev.endCall()
	dev.readStarted <- struct{}{}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case packet := <-dev.reads:
		return copy(buffer, packet), nil
	case <-dev.closed:
		return 0, transport.Disconnected(errors.New("fake device closed"))
	case <-timer.C:
		return 0, hid.ErrTimeout
	}
}

func (dev *fakeHIDDevice) Close() error {
	dev.mu.Lock()
	dev.closeCalls++
	if dev.active != 0 {
		dev.violations++
	}
	dev.closeOnce.Do(func() { close(dev.closed) })
	dev.mu.Unlock()
	return dev.closeErr
}

func (dev *fakeHIDDevice) beginCall() error {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	select {
	case <-dev.closed:
		dev.violations++
		return transport.Disconnected(errors.New("fake device closed"))
	default:
		dev.active++
		return nil
	}
}

func (dev *fakeHIDDevice) endCall() {
	dev.mu.Lock()
	dev.active--
	dev.mu.Unlock()
}

func (dev *fakeHIDDevice) writtenPackets() [][]byte {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	packets := make([][]byte, len(dev.writes))
	for i, report := range dev.writes {
		packets[i] = append([]byte(nil), report[1:]...)
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
	session := &hidSession{dev: dev, channelID: testChannelID, reportSize: hidReportSize}
	t.Cleanup(func() {
		_ = session.Close()
		dev.mu.Lock()
		defer dev.mu.Unlock()
		if dev.active != 0 || dev.violations != 0 || dev.closeCalls != 1 {
			t.Errorf("native lifetime: active=%d, unsafe accesses=%d, closes=%d", dev.active, dev.violations, dev.closeCalls)
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
			response = []byte{0xaa}
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
	want := []byte{hidCommandInit, 0xc2, hidCommandMsg, hidCommandCBOR, hidCommandCBOR, 0xc2}
	if len(packets) != len(want) {
		t.Fatalf("packet count = %d, want %d", len(packets), len(want))
	}
	for i, command := range want {
		if packets[i][4] != command {
			t.Fatalf("packet %d command = %02x, want %02x", i, packets[i][4], command)
		}
	}
	if !bytes.Equal(packets[2][7:12], []byte{0, 3, 0, 0, 0}) || !bytes.Equal(packets[4][7:9], []byte{0x42, 0xa0}) {
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
	for _, kind := range []string{"channel", "command", "sequence", "short", "error length"} {
		t.Run(kind, func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			packets := framedHIDPayload(t, testChannelID, 0xc2, bytes.Repeat([]byte{0xaa}, 100))
			switch kind {
			case "channel":
				packets[0][0] ^= 0xff
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
			if _, err := session.ExchangeHID(context.Background(), 0x42, nil); err == nil || !strings.Contains(err.Error(), kind) {
				t.Fatalf("init error = %v, want %s", err, kind)
			}
			if packets := dev.writtenPackets(); len(packets) != 1 || packets[0][4] != hidCommandInit {
				t.Fatal("vendor request sent after invalid initialization")
			}
		})
	}
}
