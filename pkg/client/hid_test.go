package client_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/middleware"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

type hidSession struct {
	*mockSession
	invoke func(context.Context, byte, []byte) ([]byte, error)
}

func (session *hidSession) ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	return session.invoke(ctx, command, payload)
}

func TestExchangeHIDDoesNotRequireInvokersOrProbing(t *testing.T) {
	t.Parallel()
	request, response := []byte{0x00}, []byte{0x06, 0x02, 0x04, 1, 2, 3, 4}
	session := &hidSession{
		mockSession: &mockSession{exchange: func(context.Context, []byte) ([]byte, error) {
			t.Error("explicit HID exchange invoked the ordinary exchange path")
			return nil, nil
		}},
		invoke: func(_ context.Context, command byte, payload []byte) ([]byte, error) {
			if command != 0x42 || !bytes.Equal(payload, request) {
				t.Fatalf("HID request = %02x %x", command, payload)
			}
			return response, nil
		},
	}
	sdk, err := client.New(session)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.ExchangeHID(context.Background(), sdk, 0x42, request)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("ExchangeHID = %x, %v; want unchanged response %x", got, err, response)
	}
}

func TestExchangeHIDKeepsMiddlewareAndCTAPInvocationsSeparate(t *testing.T) {
	t.Parallel()
	var order []string
	var ordinary [][]byte
	session := &hidSession{
		mockSession: &mockSession{exchange: func(_ context.Context, request []byte) ([]byte, error) {
			ordinary = append(ordinary, append([]byte(nil), request...))
			return request, nil
		}},
		invoke: func(_ context.Context, command byte, payload []byte) ([]byte, error) {
			order = append(order, "device")
			if command != 0x42 || !bytes.Equal(payload, []byte{0x00}) {
				t.Fatalf("HID request = %02x %x", command, payload)
			}
			return []byte{0x6a, 0x80}, nil
		},
	}
	legacyCalls := 0
	legacy := middleware.Func(func(next middleware.ExchangeFunc) middleware.ExchangeFunc {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			legacyCalls++
			return next(ctx, payload)
		}
	})
	wrap := func(name string) middleware.HIDFunc {
		return func(next middleware.HIDExchangeFunc) middleware.HIDExchangeFunc {
			return func(ctx context.Context, command byte, payload []byte) ([]byte, error) {
				order = append(order, name+" before")
				response, err := next(ctx, command, payload)
				order = append(order, name+" after")
				return response, err
			}
		}
	}
	sdk, err := client.New(session, client.WithDefaultRawInvokers(), client.WithMiddleware(legacy),
		client.WithHIDMiddleware(wrap("first")), client.WithHIDMiddleware(wrap("second")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExchangeHID(context.Background(), sdk, 0x42, []byte{0x00}); err != nil {
		t.Fatal(err)
	}
	if legacyCalls != 0 {
		t.Fatal("legacy middleware received a vendor payload")
	}
	wantOrder := []string{"first before", "second before", "device", "second after", "first after"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("middleware order = %v, want %v", order, wantOrder)
	}
	// CTAP2 command 0x42 must remain an application command inside CBOR.
	if _, err := sdk.InvokeRaw(context.Background(), client.FamilyCTAP2, 0x42, []byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.InvokeRaw(context.Background(), client.FamilyCTAP1, 0x03, nil); err != nil {
		t.Fatal(err)
	}
	wantOrdinary := [][]byte{{0x42, 0xa0}, {0x00, 0x03, 0x00, 0x00, 0x00}}
	if legacyCalls != 2 || !reflect.DeepEqual(ordinary, wantOrdinary) || !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("ordinary calls = %x, legacy = %d, HID order = %v", ordinary, legacyCalls, order)
	}
}

// legacyClient intentionally implements only the original Client interface.
type legacyClient struct{ client.Client }

type customHIDClient struct {
	client.Client
	invoke func(context.Context, byte, []byte) ([]byte, error)
}

func (sdk customHIDClient) ExchangeHID(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	return sdk.invoke(ctx, command, payload)
}

func TestExchangeHIDSupportsThirdPartyClientsAndPreservesErrors(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), struct{}{}, "context marker")
	failure := &usb.HIDError{Code: 0x01}
	sdk := customHIDClient{invoke: func(got context.Context, command byte, payload []byte) ([]byte, error) {
		if got != ctx || command != 0x42 || len(payload) != 0 {
			t.Fatal("helper changed the context, command or payload")
		}
		return nil, transport.Wrap("fake exchange", failure)
	}}
	_, err := client.ExchangeHID(ctx, sdk, 0x42, nil)
	var hidError *usb.HIDError
	if !errors.As(err, &hidError) || hidError != failure {
		t.Fatalf("error = %v, want original HIDError", err)
	}
}

func TestExchangeHIDReportsUnsupportedSessionsAndClients(t *testing.T) {
	t.Parallel()
	for _, kind := range []transport.Kind{transport.KindUSB, transport.KindNFC, transport.KindBLE} {
		t.Run(string(kind), func(t *testing.T) {
			sdk, err := client.New(&mockSession{device: transport.DeviceDescriptor{Transport: kind}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ExchangeHID(context.Background(), sdk, 0x42, nil)
			var transportError *transport.Error
			if !errors.Is(err, transport.ErrUnsupported) || !errors.As(err, &transportError) {
				t.Fatalf("error = %v, want typed unsupported transport error", err)
			}
		})
	}
	for _, sdk := range []client.Client{legacyClient{}, nil} {
		if _, err := client.ExchangeHID(context.Background(), sdk, 0x42, nil); !errors.Is(err, transport.ErrUnsupported) {
			t.Fatalf("legacy/nil client error = %v", err)
		}
	}
}

func TestExchangeHIDHonorsCanceledContextBeforeDispatch(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sdk := customHIDClient{invoke: func(context.Context, byte, []byte) ([]byte, error) {
		t.Fatal("canceled call reached the client")
		return nil, nil
	}}
	if _, err := client.ExchangeHID(ctx, sdk, 0x42, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want canceled", err)
	}
}

func TestWithHIDMiddlewareRejectsNil(t *testing.T) {
	t.Parallel()
	_, err := client.New(&mockSession{}, client.WithHIDMiddleware(nil))
	if !errors.Is(err, client.ErrMiddlewareRequired) {
		t.Fatalf("error = %v, want ErrMiddlewareRequired", err)
	}
}

func TestHIDClientDirectCallHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	sdk, err := client.New(&hidSession{mockSession: &mockSession{}, invoke: func(context.Context, byte, []byte) ([]byte, error) {
		t.Fatal("canceled direct HIDClient call reached the session")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sdk.(client.HIDClient).ExchangeHID(ctx, 0x42, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want canceled", err)
	}
}
