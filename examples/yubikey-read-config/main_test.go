package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type configSession struct {
	response []byte
	err      error
}

func (session *configSession) Device() transport.DeviceDescriptor {
	return transport.DeviceDescriptor{}
}
func (session *configSession) Close() error { return nil }
func (session *configSession) Exchange(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected ordinary CTAP exchange")
}
func (session *configSession) ExchangeHID(_ context.Context, command byte, payload []byte) ([]byte, error) {
	if command != 0x42 || !bytes.Equal(payload, []byte{0x00}) {
		return nil, errors.New("unexpected READ_CONFIG command or page")
	}
	return session.response, session.err
}

func TestReadConfigUsesExplicitVendorCommandAndValidatesLength(t *testing.T) {
	t.Parallel()
	for _, response := range [][]byte{{6, 2, 4, 0, 0, 0, 7}, nil, {3, 2, 4}, {0}} {
		sdk, err := client.New(&configSession{response: response})
		if err != nil {
			t.Fatal(err)
		}
		got, err := readConfig(context.Background(), sdk)
		valid := len(response) != 0 && int(response[0]) == len(response)-1
		if valid && (err != nil || !bytes.Equal(got, response)) || !valid && err == nil {
			t.Fatalf("response %x: got %x, %v", response, got, err)
		}
	}
}

func TestReadConfigPreservesExchangeError(t *testing.T) {
	t.Parallel()
	failure := errors.New("device failure")
	sdk, err := client.New(&configSession{err: failure})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(context.Background(), sdk); !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRequiresExplicitDeviceSelection(t *testing.T) {
	t.Parallel()
	if err := run(""); err == nil {
		t.Fatal("expected a device selection error before discovery")
	}
}
