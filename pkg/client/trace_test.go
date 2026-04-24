package client_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

func TestWithTraceRecordsExchange(t *testing.T) {
	t.Parallel()

	recorder := client.NewTraceRecorder()
	session := &flowSession{device: transport.DeviceDescriptor{ID: "dev-3"}, responses: [][]byte{{0x00}}}
	candidate, err := client.New(session, client.WithTrace(recorder), client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = candidate.InvokeRaw(context.Background(), client.FamilyCTAP2, ctap2.CommandGetInfo, nil)
	if err != nil {
		t.Fatalf("invoke raw: %v", err)
	}

	events := recorder.Events()
	if len(events) != 2 {
		t.Fatalf("unexpected trace count: %d", len(events))
	}
	if events[0].Direction != client.TraceDirectionRequest || !bytes.Equal(events[1].Payload, []byte{0x00}) {
		t.Fatal("unexpected trace content")
	}
}

func TestWithTraceRedactsSensitiveCommandsByDefault(t *testing.T) {
	t.Parallel()

	recorder := client.NewTraceRecorder()
	session := &flowSession{device: transport.DeviceDescriptor{ID: "dev-4"}, responses: [][]byte{{0x00, 0x01, 0x02}}}
	candidate, err := client.New(session, client.WithTrace(recorder), client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = candidate.InvokeRaw(context.Background(), client.FamilyCTAP2, ctap2.CommandClientPIN, []byte{0xa1, 0x02, 0x01})
	if err != nil {
		t.Fatalf("invoke raw: %v", err)
	}

	events := recorder.Events()
	if len(events) != 2 {
		t.Fatalf("unexpected trace count: %d", len(events))
	}
	for _, event := range events {
		if !event.Redacted {
			t.Fatalf("event was not redacted: %#v", event)
		}
		if len(event.Payload) != 0 {
			t.Fatalf("redacted event retained payload: %x", event.Payload)
		}
		if event.Command != ctap2.CommandClientPIN {
			t.Fatalf("command = 0x%02x, want 0x%02x", event.Command, ctap2.CommandClientPIN)
		}
	}
}

func TestWithTraceAllowsUnsafeRawPayloads(t *testing.T) {
	t.Parallel()

	recorder := client.NewTraceRecorder()
	session := &flowSession{device: transport.DeviceDescriptor{ID: "dev-5"}, responses: [][]byte{{0x00, 0x01, 0x02}}}
	candidate, err := client.New(session, client.WithTrace(recorder, client.TraceOptions{RedactSecrets: false}), client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = candidate.InvokeRaw(context.Background(), client.FamilyCTAP2, ctap2.CommandClientPIN, []byte{0xa1, 0x02, 0x01})
	if err != nil {
		t.Fatalf("invoke raw: %v", err)
	}

	events := recorder.Events()
	if len(events) != 2 {
		t.Fatalf("unexpected trace count: %d", len(events))
	}
	if events[0].Redacted || !bytes.Equal(events[0].Payload, []byte{ctap2.CommandClientPIN, 0xa1, 0x02, 0x01}) {
		t.Fatalf("unexpected request event: %#v", events[0])
	}
}
