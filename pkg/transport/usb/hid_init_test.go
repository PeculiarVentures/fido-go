package usb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	hid "github.com/sstallion/go-hid"
)

func TestReadHIDMessageFiltersForeignReportsThroughoutResponse(t *testing.T) {
	t.Parallel()
	const foreignChannel = testChannelID + 1
	want := bytes.Repeat([]byte{0xab}, 150)
	var packets [][]byte
	for _, packet := range framedHIDPayload(t, testChannelID, 0xc2, want) {
		// Include foreign errors, keepalives, initial and continuation reports.
		for _, command := range []byte{hidCommandError, hidCommandKeepalive, 0xc2} {
			packets = append(packets, framedHIDPayload(t, foreignChannel, command, bytes.Repeat([]byte{1}, 100))...)
		}
		packets = append(packets, packet)
	}
	index := 0
	got, err := readHIDMessage(context.Background(), hidReportSize, testChannelID, 0xc2, func(context.Context) ([]byte, error) {
		if index == len(packets) {
			return nil, errors.New("response exhausted")
		}
		packet := packets[index]
		index++
		return packet, nil
	})
	if err != nil || !bytes.Equal(got, want) || index != len(packets) {
		t.Fatalf("response = %x, %v; consumed=%d/%d", got, err, index, len(packets))
	}
}

func TestHIDInitializationRecoversBeforeSendingApplicationRequest(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	session.channelID = 0
	initCalls, pingCalls, applicationCalls := 0, 0, 0
	var allocated uint32
	queue := func(command byte, payload []byte) {
		for _, reply := range framedHIDPayload(t, allocated, command, payload) {
			dev.reads <- reply
		}
	}
	dev.onWrite = func(packet []byte) error {
		channel, command := binary.BigEndian.Uint32(packet[:4]), packet[4]
		switch command {
		case hidCommandInit:
			initCalls++
			if channel != hidBroadcastCID {
				return fmt.Errorf("INIT channel = %08x", channel)
			}
			if initCalls == 1 {
				return nil // The interrupted transaction caused this INIT to be dropped.
			}
			if initCalls < 3 {
				for _, reply := range framedHIDPayload(t, channel, hidCommandError, []byte{hidErrorChannelBusy}) {
					dev.reads <- reply
				}
				return nil
			}
			queueHIDPayload(t, dev, hidCommandCBOR, bytes.Repeat([]byte{0xaa}, 180))
			response := append([]byte(nil), packet[7:15]...)
			allocated = testChannelID + uint32(initCalls)
			response = binary.BigEndian.AppendUint32(response, allocated)
			response = append(response, 2, 5, 4, 3, 4, 0, 0) // Future INIT extensions are accepted.
			stale := append([]byte(nil), response...)
			stale[0] ^= 0xff
			for _, payload := range [][]byte{stale, response} {
				for _, reply := range framedHIDPayload(t, channel, command, payload) {
					dev.reads <- reply
				}
			}
		case hidCommandPing:
			pingCalls++
			if channel != allocated || binary.BigEndian.Uint16(packet[5:7]) != 0 {
				return errors.New("invalid readiness PING")
			}
			if pingCalls == 1 {
				return nil // A lost readiness response is also safe to retry.
			}
			if pingCalls < 3 {
				queue(hidCommandError, []byte{hidErrorChannelBusy})
			} else {
				queue(command, nil)
			}
		default:
			applicationCalls++
			if initCalls != 5 || pingCalls != 3 || channel != allocated || command != 0xc2 {
				return errors.New("application request sent before channel was ready")
			}
			queue(command, []byte{0x42})
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range 2 {
		got, err := session.ExchangeHID(ctx, 0x42, []byte{0})
		if err != nil || !bytes.Equal(got, []byte{0x42}) {
			t.Fatalf("exchange = %x, %v", got, err)
		}
	}
	if initCalls != 5 || pingCalls != 3 || applicationCalls != 2 {
		t.Fatalf("INIT/PING/application writes = %d/%d/%d", initCalls, pingCalls, applicationCalls)
	}
}

func TestHIDInitializationRejectsInvalidAllocatedChannelAndPingEcho(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"zero channel", "broadcast channel", "short response", "bad ping echo"} {
		t.Run(kind, func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			session.channelID = 0
			dev.onWrite = func(packet []byte) error {
				if packet[4] == hidCommandInit {
					channel := testChannelID
					if kind == "zero channel" {
						channel = 0
					} else if kind == "broadcast channel" {
						channel = hidBroadcastCID
					}
					response := append([]byte(nil), packet[7:15]...)
					response = binary.BigEndian.AppendUint32(response, channel)
					if kind != "short response" {
						response = append(response, 2, 5, 4, 3, 4)
					}
					for _, reply := range framedHIDPayload(t, hidBroadcastCID, hidCommandInit, response) {
						dev.reads <- reply
					}
				} else if packet[4] == hidCommandPing {
					queueHIDPayload(t, dev, hidCommandPing, []byte{1})
				} else {
					t.Error("application request sent after invalid handshake")
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if got, err := session.ExchangeHID(ctx, 0x42, nil); err == nil || got != nil || session.channelID != 0 {
				t.Fatalf("invalid handshake = %x, %v; channel=%08x", got, err, session.channelID)
			}
		})
	}
}

func TestHIDInitializationBusyRecoveryIsBoundedAndCancelable(t *testing.T) {
	t.Parallel()
	calls := 0
	busy := &HIDError{Code: hidErrorChannelBusy}
	_, err := retryHIDHandshake(context.Background(), func() ([]byte, error) {
		calls++
		return nil, busy
	})
	if !errors.Is(err, busy) || calls != hidInitBusyRetries+1 {
		t.Fatalf("busy recovery: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = retryHIDHandshake(ctx, func() ([]byte, error) {
		calls++
		cancel()
		return nil, busy
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled recovery: calls=%d err=%v", calls, err)
	}
	failure := &HIDError{Code: 1}
	calls = 0
	_, err = retryHIDHandshake(context.Background(), func() ([]byte, error) {
		calls++
		return nil, failure
	})
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("non-busy error retried: calls=%d err=%v", calls, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	calls = 0
	_, err = retryHIDHandshake(ctx, func() ([]byte, error) {
		calls++
		if calls == 2 {
			return []byte{1}, nil
		}
		return nil, hid.ErrTimeout
	})
	if err != nil || calls != 2 {
		t.Fatalf("local handshake timeout: calls=%d err=%v", calls, err)
	}
}

func TestHIDApplicationBusyIsNeverRetried(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	queueHIDPayload(t, dev, hidCommandError, []byte{hidErrorChannelBusy})
	_, err := session.ExchangeHID(context.Background(), 0x42, []byte{1})
	var hidErr *HIDError
	if !errors.As(err, &hidErr) || hidErr.Code != hidErrorChannelBusy || len(dev.writtenPackets()) != 1 {
		t.Fatalf("application busy: writes=%d err=%v", len(dev.writtenPackets()), err)
	}
}

func TestHIDForeignTrafficDoesNotPreventCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	foreign := framedHIDPayload(t, testChannelID+1, hidCommandCBOR, nil)[0]
	reads := 0
	_, err := readHIDMessage(ctx, hidReportSize, testChannelID, hidCommandCBOR, func(context.Context) ([]byte, error) {
		reads++
		if reads == 5 {
			cancel()
		}
		return foreign, nil
	})
	if !errors.Is(err, context.Canceled) || reads != 5 {
		t.Fatalf("foreign traffic cancellation: reads=%d err=%v", reads, err)
	}
}

func TestHIDApplicationReadIsNotLimitedToHandshakeResponseWait(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	dev.onWrite = func([]byte) error {
		go func() {
			time.Sleep(hidInitResponseWait + 100*time.Millisecond)
			queueHIDPayload(t, dev, 0xc2, []byte{0x42})
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := session.ExchangeHID(ctx, 0x42, nil)
	if err != nil || !bytes.Equal(got, []byte{0x42}) || len(dev.writtenPackets()) != 1 {
		t.Fatalf("slow application response = %x, %v; writes=%d", got, err, len(dev.writtenPackets()))
	}
}

func TestHIDLateReadinessReplyCannotPoisonApplicationChannel(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	session.channelID = 0
	allocated := testChannelID
	var timedOutChannel uint32
	initCalls, pingCalls, applicationCalls := 0, 0, 0
	dev.onWrite = func(packet []byte) error {
		channel := binary.BigEndian.Uint32(packet[:4])
		switch packet[4] {
		case hidCommandInit:
			initCalls++
			allocated++ // Allocated CIDs are unique across handshake attempts.
			response := append([]byte(nil), packet[7:15]...)
			response = binary.BigEndian.AppendUint32(response, allocated)
			response = append(response, 2, 5, 4, 3, 4)
			for _, reply := range framedHIDPayload(t, hidBroadcastCID, hidCommandInit, response) {
				dev.reads <- reply
			}
		case hidCommandPing:
			pingCalls++
			if pingCalls == 1 {
				timedOutChannel = channel
				return nil
			}
			// Deliver the first reply only after the next PING has been sent.
			// A retry on the same CID would leave the second echo to poison
			// the following application exchange.
			for _, cid := range []uint32{timedOutChannel, channel, timedOutChannel} {
				for _, reply := range framedHIDPayload(t, cid, hidCommandPing, nil) {
					dev.reads <- reply
				}
			}
		default:
			applicationCalls++
			for _, reply := range framedHIDPayload(t, channel, packet[4], []byte{0x42}) {
				dev.reads <- reply
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := session.ExchangeHID(ctx, 0x42, nil)
	if err != nil || !bytes.Equal(got, []byte{0x42}) || initCalls != 2 || pingCalls != 2 || applicationCalls != 1 {
		t.Fatalf("late readiness response: %x, %v; INIT/PING/application=%d/%d/%d", got, err, initCalls, pingCalls, applicationCalls)
	}
}
