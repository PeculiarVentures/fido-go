package client_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/fxamacker/cbor/v2"
)

type flowSession struct {
	device    transport.DeviceDescriptor
	requests  [][]byte
	responses [][]byte
}

func (session *flowSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *flowSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	_ = ctx
	session.requests = append(session.requests, append([]byte(nil), req...))
	response := session.responses[0]
	session.responses = session.responses[1:]
	return append([]byte(nil), response...), nil
}

func (session *flowSession) Close() error {
	return nil
}

func TestClientRegisterUsesCTAP2WhenAvailable(t *testing.T) {
	t.Parallel()

	responsePayload, err := cbor.Marshal(map[uint64]any{1: "packed", 2: []byte{0x01}, 3: map[string]any{"sig": []byte{0x02}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	getInfoPayload, err := cbor.Marshal(map[uint64]any{1: []string{"FIDO_2_0"}, 3: bytes.Repeat([]byte{0xAA}, 16)})
	if err != nil {
		t.Fatalf("marshal getInfo: %v", err)
	}

	session := &flowSession{
		device: transport.DeviceDescriptor{ID: "dev-1", Transport: transport.KindUSB},
		responses: [][]byte{
			append([]byte{0x00}, getInfoPayload...),
			append([]byte{0x00}, responsePayload...),
		},
	}
	candidate, err := client.New(session, client.WithRawInvoker(ctap2OnlyInvoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	result, err := candidate.Register(context.Background(), client.RegisterRequest{
		ChallengeHash: bytes.Repeat([]byte{0x11}, 32),
		RPID:          "example.com",
		UserID:        []byte{0x01},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.Protocol != client.FamilyCTAP2 || result.CTAP2 == nil {
		t.Fatal("expected ctap2 registration result")
	}
	if len(session.requests) == 0 || session.requests[0][0] != ctap2.CommandGetInfo {
		t.Fatal("expected capability probe before registration")
	}
}

func TestClientAuthenticateFallsBackToCTAP1(t *testing.T) {
	t.Parallel()

	response := []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x30, 0x44, 0x90, 0x00}
	session := &flowSession{
		device: transport.DeviceDescriptor{ID: "dev-2", Transport: transport.KindUSB},
		responses: [][]byte{
			append([]byte("U2F_V2"), 0x90, 0x00),
			response,
		},
	}
	candidate, err := client.New(session, client.WithRawInvoker(ctap1OnlyInvoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	result, err := candidate.Authenticate(context.Background(), client.AuthenticateRequest{
		ChallengeHash: bytes.Repeat([]byte{0x22}, 32),
		AppIDHash:     bytes.Repeat([]byte{0x33}, 32),
		KeyHandle:     []byte{0x01},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Protocol != client.FamilyCTAP1 || result.CTAP1 == nil {
		t.Fatal("expected ctap1 assertion result")
	}
}

type ctap1OnlyInvoker struct{}

type ctap2OnlyInvoker struct{}

func (ctap2OnlyInvoker) Protocol() client.ProtocolFamily {
	return client.FamilyCTAP2
}

func (ctap2OnlyInvoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	request := append([]byte{command}, payload...)
	return exchange(ctx, request)
}

func (ctap1OnlyInvoker) Protocol() client.ProtocolFamily {
	return client.FamilyCTAP1
}

func (ctap1OnlyInvoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	request, err := ctap1.EncodeAPDU(command, byte(ctap1.ControlEnforceUserPresenceAndSign), 0x00, payload)
	if err != nil {
		return nil, err
	}
	return exchange(ctx, request)
}
