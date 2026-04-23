package client_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/fxamacker/cbor/v2"
)

func TestClientInvokeRawDispatchesRegisteredInvoker(t *testing.T) {
	t.Parallel()

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-1", Transport: transport.KindUSB, Product: "Security Key"},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte("resp:"), req...), nil
		},
	}

	sdk, err := client.New(session, client.WithRawInvoker(rawInvoker{family: protocol.FamilyCTAP2}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	response, err := sdk.InvokeRaw(context.Background(), protocol.FamilyCTAP2, 0x04, []byte{0xA0, 0x01})
	if err != nil {
		t.Fatalf("invoke raw: %v", err)
	}

	wantRequest := []byte{0x04, 0xA0, 0x01}
	if !bytes.Equal(session.lastRequest, wantRequest) {
		t.Fatalf("request mismatch: got % X want % X", session.lastRequest, wantRequest)
	}

	wantResponse := append([]byte("resp:"), wantRequest...)
	if !bytes.Equal(response, wantResponse) {
		t.Fatalf("response mismatch: got % X want % X", response, wantResponse)
	}

	if !client.Supported(sdk, protocol.FamilyCTAP2) {
		t.Fatal("expected CTAP2 raw invoker to be registered")
	}
	if client.Supported(sdk, protocol.FamilyCTAP1) {
		t.Fatal("did not expect CTAP1 raw invoker to be registered")
	}
}

func TestClientInvokeRawAppliesMiddleware(t *testing.T) {
	t.Parallel()

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-2", Transport: transport.KindNFC},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte(nil), req...), nil
		},
	}

	sdk, err := client.New(
		session,
		client.WithMiddleware(prefixMiddleware{prefix: []byte{0xAA}}),
		client.WithRawInvoker(rawInvoker{family: protocol.FamilyCTAP1}),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	response, err := sdk.InvokeRaw(context.Background(), protocol.FamilyCTAP1, 0x03, nil)
	if err != nil {
		t.Fatalf("invoke raw: %v", err)
	}

	want := []byte{0xAA, 0x03}
	if !bytes.Equal(session.lastRequest, want) {
		t.Fatalf("middleware request mismatch: got % X want % X", session.lastRequest, want)
	}
	if !bytes.Equal(response, want) {
		t.Fatalf("middleware response mismatch: got % X want % X", response, want)
	}
}

func TestClientInvokeRawRejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	sdk, err := client.New(&mockSession{device: transport.DeviceDescriptor{ID: "auth-3"}})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = sdk.InvokeRaw(context.Background(), protocol.FamilyCTAP2, 0x04, nil)
	var unsupported *client.UnsupportedProtocolError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected UnsupportedProtocolError, got %v", err)
	}

	_, err = sdk.InvokeRaw(context.Background(), protocol.Family("invalid"), 0x04, nil)
	var unknown *protocol.UnknownFamilyError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected UnknownFamilyError, got %v", err)
	}
}

func TestWithRawInvokerRejectsDuplicateProtocol(t *testing.T) {
	t.Parallel()

	_, err := client.New(
		&mockSession{device: transport.DeviceDescriptor{ID: "auth-4"}},
		client.WithRawInvoker(rawInvoker{family: protocol.FamilyCTAP2}),
		client.WithRawInvoker(rawInvoker{family: protocol.FamilyCTAP2}),
	)
	var duplicate *client.DuplicateRawInvokerError
	if !errors.As(err, &duplicate) {
		t.Fatalf("expected DuplicateRawInvokerError, got %v", err)
	}
}

func TestClientGetCapabilitiesPrefersCTAP2AndCaches(t *testing.T) {
	t.Parallel()

	getInfoPayload, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_1", "U2F_V2"},
		3: bytes.Repeat([]byte{0x01}, 16),
		4: map[string]bool{"clientPin": true},
	})
	if err != nil {
		t.Fatalf("marshal get info payload: %v", err)
	}
	getInfoResponse := append([]byte{0x00}, getInfoPayload...)

	var exchangeCount int
	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-5", Transport: transport.KindUSB},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			exchangeCount++
			switch {
			case bytes.Equal(req, []byte{0x04}):
				return append([]byte(nil), getInfoResponse...), nil
			case bytes.Equal(req, []byte{0x00, 0x03, 0x00, 0x00, 0x00}):
				return []byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0x00}, nil
			default:
				return nil, errors.New("unexpected request")
			}
		},
	}

	sdk, err := client.New(session, client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	caps, err := sdk.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if !caps.HasCTAP2() {
		t.Fatal("expected CTAP2 capabilities")
	}
	if !caps.HasCTAP1() {
		t.Fatal("expected CTAP1 fallback capabilities")
	}
	if family, ok := caps.PreferredProtocol(); !ok || family != protocol.FamilyCTAP2 {
		t.Fatalf("preferred protocol mismatch: %q %v", family, ok)
	}

	if _, err := sdk.Capabilities(context.Background()); err != nil {
		t.Fatalf("second Capabilities() error = %v", err)
	}
	if exchangeCount != 2 {
		t.Fatalf("expected cached capabilities after 2 exchanges, got %d", exchangeCount)
	}
}

func TestClientGetCapabilitiesFallsBackToCTAP1(t *testing.T) {
	t.Parallel()

	session := &mockSession{
		device: transport.DeviceDescriptor{ID: "auth-6", Transport: transport.KindNFC},
		exchange: func(_ context.Context, req []byte) ([]byte, error) {
			switch {
			case bytes.Equal(req, []byte{0x04}):
				return []byte{0x01}, nil
			case bytes.Equal(req, []byte{0x00, 0x03, 0x00, 0x00, 0x00}):
				return []byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0x00}, nil
			default:
				return nil, errors.New("unexpected request")
			}
		},
	}

	sdk, err := client.New(session, client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	caps, err := sdk.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if caps.HasCTAP2() {
		t.Fatal("did not expect CTAP2 capabilities")
	}
	if !caps.HasCTAP1() || caps.RawCTAP1.Version != "U2F_V2" {
		t.Fatalf("unexpected CTAP1 capabilities: %#v", caps.RawCTAP1)
	}
	if family, ok := caps.PreferredProtocol(); !ok || family != protocol.FamilyCTAP1 {
		t.Fatalf("preferred protocol mismatch: %q %v", family, ok)
	}
}

type mockSession struct {
	device      transport.DeviceDescriptor
	exchange    func(ctx context.Context, req []byte) ([]byte, error)
	lastRequest []byte
	closed      bool
}

func (session *mockSession) Device() transport.DeviceDescriptor {
	return session.device
}

func (session *mockSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	session.lastRequest = append([]byte(nil), req...)
	if session.exchange == nil {
		return nil, nil
	}
	return session.exchange(ctx, req)
}

func (session *mockSession) Close() error {
	session.closed = true
	return nil
}

type rawInvoker struct {
	family protocol.Family
}

func (invoker rawInvoker) Protocol() protocol.Family {
	return invoker.family
}

func (invoker rawInvoker) InvokeRaw(ctx context.Context, exchange middleware.ExchangeFunc, command byte, payload []byte) ([]byte, error) {
	request := append([]byte{command}, payload...)
	return exchange(ctx, request)
}

type prefixMiddleware struct {
	prefix []byte
}

func (wrapper prefixMiddleware) WrapExchange(next middleware.ExchangeFunc) middleware.ExchangeFunc {
	return func(ctx context.Context, req []byte) ([]byte, error) {
		prefixed := append(append([]byte(nil), wrapper.prefix...), req...)
		return next(ctx, prefixed)
	}
}
