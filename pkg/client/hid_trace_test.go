package client_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
)

func TestHIDTraceRedactionAndDefensiveCopies(t *testing.T) {
	t.Parallel()
	for _, unsafe := range []bool{false, true} {
		for _, command := range []byte{0x03, 0x10, 0x42} {
			t.Run(fmt.Sprintf("unsafe=%v/command=%02x", unsafe, command), func(t *testing.T) {
				request, response := []byte{0x04, 0xaa}, []byte{0x6a, 0xbb, 0xcc}
				recorder := client.NewTraceRecorder()
				option := client.WithTrace(recorder)
				if unsafe {
					option = client.WithTrace(recorder, client.TraceOptions{RedactSecrets: false})
				}
				sdk, err := client.New(&hidSession{mockSession: &mockSession{}, invoke: func(context.Context, byte, []byte) ([]byte, error) {
					return response, nil
				}}, option)
				if err != nil {
					t.Fatal(err)
				}
				got, err := client.ExchangeHID(context.Background(), sdk, command, request)
				if err != nil || !bytes.Equal(got, response) {
					t.Fatalf("exchange = %x, %v", got, err)
				}
				events := recorder.HIDEvents()
				if len(events) != 2 || len(recorder.Events()) != 0 {
					t.Fatalf("HID events = %v, ordinary = %v", events, recorder.Events())
				}
				for i, event := range events {
					want := [][]byte{request, response}[i]
					if event.Command != command || event.Redacted == unsafe || event.Length != len(want) {
						t.Fatalf("event = %#v", event)
					}
					if unsafe && !bytes.Equal(event.Payload, want) || !unsafe && len(event.Payload) != 0 {
						t.Fatalf("unexpected trace payload: %#v", event)
					}
				}
				if events[0].Direction != client.TraceDirectionRequest || events[1].Direction != client.TraceDirectionResponse {
					t.Fatal("incorrect trace directions")
				}
				request[0], response[0] = 0xff, 0xff
				if unsafe {
					events[0].Payload[0] = 0xee
					events[1].Payload[0] = 0xee
					if fresh := recorder.HIDEvents(); fresh[0].Payload[0] != 0x04 || fresh[1].Payload[0] != 0x6a {
						t.Fatalf("trace aliases caller memory: %#v", fresh)
					}
				}
				events[0].Command = 0xff
				if recorder.HIDEvents()[0].Command != command {
					t.Fatal("trace event slice aliases recorder storage")
				}
			})
		}
	}
}

func TestHIDTraceKeepsOrdinaryRedactionAndRecordsEmptyMessages(t *testing.T) {
	t.Parallel()
	recorder := client.NewTraceRecorder()
	sdk, err := client.New(&hidSession{
		mockSession: &mockSession{exchange: func(context.Context, []byte) ([]byte, error) { return []byte{0x00, 0xaa}, nil }},
		invoke:      func(context.Context, byte, []byte) ([]byte, error) { return nil, nil },
	}, client.WithDefaultRawInvokers(), client.WithTrace(recorder))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.InvokeRaw(context.Background(), client.FamilyCTAP2, 0x06, []byte{0xaa}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExchangeHID(context.Background(), sdk, 0x42, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.InvokeRaw(context.Background(), client.FamilyCTAP1, 0x03, nil); err != nil {
		t.Fatal(err)
	}
	ordinary, hid := recorder.Events(), recorder.HIDEvents()
	if len(ordinary) != 4 || len(hid) != 2 {
		t.Fatalf("ordinary/HID counts = %d/%d", len(ordinary), len(hid))
	}
	for _, event := range ordinary[:2] {
		if !event.Redacted || len(event.Payload) != 0 || event.Command != 0x06 {
			t.Fatalf("ClientPIN trace leaked: %#v", event)
		}
	}
	if ordinary[2].Redacted || !bytes.Equal(ordinary[2].Payload, []byte{0, 3, 0, 0, 0}) {
		t.Fatalf("CTAP1 trace changed: %#v", ordinary[2])
	}
	for _, event := range hid {
		if !event.Redacted || len(event.Payload) != 0 || event.Length != 0 || event.Command != 0x42 {
			t.Fatalf("empty HID event = %#v", event)
		}
	}
}

func TestHIDTracePreservesErrorsAndRedactsReturnedData(t *testing.T) {
	t.Parallel()
	recorder := client.NewTraceRecorder()
	failure := errors.New("synthetic transport failure")
	sdk, err := client.New(&hidSession{mockSession: &mockSession{}, invoke: func(context.Context, byte, []byte) ([]byte, error) {
		return []byte{0xaa, 0xbb}, failure
	}}, client.WithTrace(recorder))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExchangeHID(context.Background(), sdk, 0x42, []byte{0x01}); !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
	events := recorder.HIDEvents()
	if len(events) != 2 || events[1].Length != 2 || !events[1].Redacted || len(events[1].Payload) != 0 {
		t.Fatalf("error response trace = %#v", events)
	}
}
