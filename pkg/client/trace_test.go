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
