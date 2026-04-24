package usb

import (
	"bytes"
	"context"
	"errors"
	"testing"

	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func TestHIDCommandForRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     []byte
		command byte
	}{
		{
			name:    "ctap1 version short apdu",
			req:     []byte{0x00, 0x03, 0x00, 0x00},
			command: hidCommandMsg,
		},
		{
			name:    "ctap1 authenticate apdu",
			req:     []byte{0x00, 0x02, 0x03, 0x00, 0x00},
			command: hidCommandMsg,
		},
		{
			name:    "ctap2 getInfo",
			req:     []byte{0x04},
			command: hidCommandCBOR,
		},
		{
			name:    "ctap2 clientPIN",
			req:     []byte{0x06, 0xa1, 0x01, 0x01},
			command: hidCommandCBOR,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := hidCommandForRequest(test.req); got != test.command {
				t.Fatalf("hidCommandForRequest(%x) = 0x%02x, want 0x%02x", test.req, got, test.command)
			}
		})
	}
}

func TestReadHIDMessageSkipsKeepalive(t *testing.T) {
	t.Parallel()

	const (
		reportSize = 16
		channelID  = 0x01020304
	)
	keepaliveCodec, err := wirehid.NewCodec(channelID, hidCommandKeepalive, reportSize)
	if err != nil {
		t.Fatalf("NewCodec(keepalive) error = %v", err)
	}
	keepalivePackets, err := keepaliveCodec.Fragment([]byte{0x02})
	if err != nil {
		t.Fatalf("Fragment(keepalive) error = %v", err)
	}

	responsePayload := bytes.Repeat([]byte{0xAB}, 20)
	responseCodec, err := wirehid.NewCodec(channelID, hidCommandCBOR, reportSize)
	if err != nil {
		t.Fatalf("NewCodec(response) error = %v", err)
	}
	responsePackets, err := responseCodec.Fragment(responsePayload)
	if err != nil {
		t.Fatalf("Fragment(response) error = %v", err)
	}

	packets := append(append([][]byte{}, keepalivePackets...), responsePackets...)
	index := 0
	payload, err := readHIDMessage(context.Background(), reportSize, channelID, hidCommandCBOR, func(context.Context) ([]byte, error) {
		packet := packets[index]
		index++
		return append([]byte(nil), packet...), nil
	})
	if err != nil {
		t.Fatalf("readHIDMessage() error = %v", err)
	}
	if !bytes.Equal(payload, responsePayload) {
		t.Fatalf("payload = %x, want %x", payload, responsePayload)
	}
	if index != len(packets) {
		t.Fatalf("packets consumed = %d, want %d", index, len(packets))
	}
}

func TestReadHIDMessageReturnsCTAPHIDError(t *testing.T) {
	t.Parallel()

	const (
		reportSize = 16
		channelID  = 0x01020304
	)
	errorCodec, err := wirehid.NewCodec(channelID, hidCommandError, reportSize)
	if err != nil {
		t.Fatalf("NewCodec(error) error = %v", err)
	}
	errorPackets, err := errorCodec.Fragment([]byte{0x7F})
	if err != nil {
		t.Fatalf("Fragment(error) error = %v", err)
	}

	_, err = readHIDMessage(context.Background(), reportSize, channelID, hidCommandCBOR, func(context.Context) ([]byte, error) {
		return append([]byte(nil), errorPackets[0]...), nil
	})
	var hidErr *HIDError
	if !errors.As(err, &hidErr) {
		t.Fatalf("readHIDMessage() error = %v, want HIDError", err)
	}
	if hidErr.Code != 0x7F {
		t.Fatalf("hid error code = 0x%02x, want 0x7f", hidErr.Code)
	}
}

func TestRunCancelableHIDCallClosesDeviceOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	closeCalls := 0
	cancel()

	_, err := runCancelableHIDCall(ctx, func() (int, error) {
		<-closed
		return 0, errors.New("device closed")
	}, func() error {
		closeCalls++
		close(closed)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runCancelableHIDCall() error = %v, want context.Canceled", err)
	}
	if closeCalls != 1 {
		t.Fatalf("closeCalls = %d, want 1", closeCalls)
	}
}
