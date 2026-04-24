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

	authData := make([]byte, 32+1+4+16+2+1)
	authData[32] = 0x41
	authData[53] = 0x00
	authData[54] = 0x01
	authData[55] = 0x42

	responsePayload, err := cbor.Marshal(map[uint64]any{1: "packed", 2: authData, 3: map[string]any{"sig": []byte{0x02}}})
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
		User:          client.User{ID: []byte{0x01}},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.Protocol != client.FamilyCTAP2 || result.RawCTAP2 == nil {
		t.Fatal("expected ctap2 registration result")
	}
	if !bytes.Equal(result.CredentialID, []byte{0x42}) {
		t.Fatalf("CredentialID = %x, want 42", result.CredentialID)
	}
	if result.AttestationFormat != "packed" {
		t.Fatalf("AttestationFormat = %q, want packed", result.AttestationFormat)
	}
	if !result.UserPresent {
		t.Fatal("expected UserPresent to be true")
	}
	if result.UserVerified {
		t.Fatal("expected UserVerified to be false")
	}
	if len(session.requests) == 0 || session.requests[0][0] != ctap2.CommandGetInfo {
		t.Fatal("expected capability probe before registration")
	}
}

func TestClientRegisterRequestsResidentKeyWhenConfigured(t *testing.T) {
	t.Parallel()

	authData := make([]byte, 32+1+4+16+2+1)
	authData[32] = 0x41
	authData[53] = 0x00
	authData[54] = 0x01
	authData[55] = 0x42

	responsePayload, err := cbor.Marshal(map[uint64]any{1: "packed", 2: authData, 3: map[string]any{"sig": []byte{0x02}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	getInfoPayload, err := cbor.Marshal(map[uint64]any{1: []string{"FIDO_2_1"}, 3: bytes.Repeat([]byte{0xAA}, 16)})
	if err != nil {
		t.Fatalf("marshal getInfo: %v", err)
	}

	session := &flowSession{
		device: transport.DeviceDescriptor{ID: "dev-rk", Transport: transport.KindUSB},
		responses: [][]byte{
			append([]byte{0x00}, getInfoPayload...),
			append([]byte{0x00}, responsePayload...),
		},
	}
	candidate, err := client.New(session, client.WithRawInvoker(ctap2OnlyInvoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = candidate.Register(context.Background(), client.RegisterRequest{
		ChallengeHash: bytes.Repeat([]byte{0x11}, 32),
		RPID:          "example.com",
		User:          client.User{ID: []byte{0x01}},
		CTAP2: &client.CTAP2RegistrationOptions{
			ResidentKey: true,
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if len(session.requests) < 2 {
		t.Fatalf("requests = %d, want at least 2", len(session.requests))
	}
	var request struct {
		Options *ctap2.MakeCredentialOptions `cbor:"7,keyasint,omitempty"`
	}
	if err := cbor.Unmarshal(session.requests[1][1:], &request); err != nil {
		t.Fatalf("unmarshal makeCredential request: %v", err)
	}
	if request.Options == nil || !request.Options.ResidentKey {
		t.Fatalf("ResidentKey = %v, want true", request.Options)
	}
}

func TestClientAuthenticateUsesCTAP2WhenAvailable(t *testing.T) {
	t.Parallel()

	authData := make([]byte, 37)
	authData[32] = 0x05
	authData[33] = 0x00
	authData[34] = 0x00
	authData[35] = 0x00
	authData[36] = 0x07

	responsePayload, err := cbor.Marshal(map[uint64]any{
		1: map[string]any{"type": "public-key", "id": []byte{0xAA}},
		2: authData,
		3: []byte{0x30, 0x44},
	})
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}

	getInfoPayload, err := cbor.Marshal(map[uint64]any{1: []string{"FIDO_2_0"}, 3: bytes.Repeat([]byte{0xAA}, 16)})
	if err != nil {
		t.Fatalf("marshal getInfo: %v", err)
	}

	session := &flowSession{
		device: transport.DeviceDescriptor{ID: "dev-3", Transport: transport.KindUSB},
		responses: [][]byte{
			append([]byte{0x00}, getInfoPayload...),
			append([]byte{0x00}, responsePayload...),
		},
	}
	candidate, err := client.New(session, client.WithRawInvoker(ctap2OnlyInvoker{}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	result, err := candidate.Authenticate(context.Background(), client.AuthenticateRequest{
		ChallengeHash: bytes.Repeat([]byte{0x22}, 32),
		RPID:          "example.com",
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Protocol != client.FamilyCTAP2 || result.RawCTAP2 == nil {
		t.Fatal("expected ctap2 assertion result")
	}
	if !bytes.Equal(result.CredentialID, []byte{0xAA}) {
		t.Fatalf("CredentialID = %x, want aa", result.CredentialID)
	}
	if !bytes.Equal(result.Signature, []byte{0x30, 0x44}) {
		t.Fatalf("Signature = %x, want 3044", result.Signature)
	}
	if result.SignCount != 7 {
		t.Fatalf("SignCount = %d, want 7", result.SignCount)
	}
	if !result.UserPresent {
		t.Fatal("expected UserPresent to be true")
	}
	if !result.UserVerified {
		t.Fatal("expected UserVerified to be true")
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
		CTAP1: &client.CTAP1AuthenticationOptions{
			AppIDHash: bytes.Repeat([]byte{0x33}, 32),
			KeyHandle: []byte{0x01},
		},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Protocol != client.FamilyCTAP1 || result.RawCTAP1 == nil {
		t.Fatal("expected ctap1 assertion result")
	}
	if !bytes.Equal(result.CredentialID, []byte{0x01}) {
		t.Fatalf("CredentialID = %x, want 01", result.CredentialID)
	}
	if !bytes.Equal(result.Signature, []byte{0x30, 0x44}) {
		t.Fatalf("Signature = %x, want 3044", result.Signature)
	}
	if result.SignCount != 2 {
		t.Fatalf("SignCount = %d, want 2", result.SignCount)
	}
	if !result.UserPresent {
		t.Fatal("expected UserPresent to be true")
	}
	if result.UserVerified {
		t.Fatal("expected UserVerified to be false")
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
