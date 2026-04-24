package nfc_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
	transportnfc "github.com/PeculiarVentures/fido-go/pkg/transport/nfc"
)

var fidoAppletSelect = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00}

type fakePCSCFactory struct {
	contexts []*fakePCSCContext
	index    int
}

func (factory *fakePCSCFactory) New() (transportnfc.PCSCContext, error) {
	if factory.index >= len(factory.contexts) {
		return nil, errors.New("unexpected pcsc context request")
	}
	ctx := factory.contexts[factory.index]
	factory.index++
	return ctx, nil
}

type fakePCSCContext struct {
	readers  []string
	cards    map[string]*fakePCSCCard
	released bool
}

func (ctx *fakePCSCContext) ListReaders() ([]string, error) {
	return append([]string(nil), ctx.readers...), nil
}

func (ctx *fakePCSCContext) Connect(reader string) (transportnfc.PCSCCard, error) {
	card, ok := ctx.cards[reader]
	if !ok {
		return nil, errors.New("no card present")
	}
	return card, nil
}

func (ctx *fakePCSCContext) Release() error {
	ctx.released = true
	return nil
}

type fakePCSCCard struct {
	responses [][]byte
	requests  [][]byte
	closed    bool
}

func (card *fakePCSCCard) Transmit(command []byte) ([]byte, error) {
	card.requests = append(card.requests, append([]byte(nil), command...))
	if len(card.responses) == 0 {
		return nil, errors.New("unexpected transmit")
	}
	response := append([]byte(nil), card.responses[0]...)
	card.responses = card.responses[1:]
	return response, nil
}

func (card *fakePCSCCard) Close() error {
	card.closed = true
	return nil
}

func TestPCSCBackendDiscoverFiltersReadersByFIDOApplet(t *testing.T) {
	t.Parallel()

	readerOK := &fakePCSCCard{responses: [][]byte{{0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00}}}
	readerNoFIDO := &fakePCSCCard{responses: [][]byte{{0x6A, 0x82}}}
	factory := &fakePCSCFactory{contexts: []*fakePCSCContext{{
		readers: []string{"Reader One", "Reader Two"},
		cards: map[string]*fakePCSCCard{
			"Reader One": readerOK,
			"Reader Two": readerNoFIDO,
		},
	}}}

	backend, err := transportnfc.NewPCSCBackendWithFactory(factory.New)
	if err != nil {
		t.Fatalf("NewPCSCBackendWithFactory() error = %v", err)
	}

	devices, err := backend.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].ID != "pcsc:Reader One" {
		t.Fatalf("device ID = %q", devices[0].ID)
	}
	if devices[0].Transport != transport.KindNFC {
		t.Fatalf("device transport = %q", devices[0].Transport)
	}
	if !bytes.Equal(readerOK.requests[0], fidoAppletSelect) {
		t.Fatalf("select APDU = %x, want %x", readerOK.requests[0], fidoAppletSelect)
	}
	if !readerOK.closed || !readerNoFIDO.closed {
		t.Fatal("discovery should close probed cards")
	}
	if !factory.contexts[0].released {
		t.Fatal("discovery should release the PC/SC context")
	}
}

func TestPCSCBackendOpenSelectsAppletAndExchangesAPDUs(t *testing.T) {
	t.Parallel()

	card := &fakePCSCCard{responses: [][]byte{{0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00}, {0xAA, 0x90, 0x00}}}
	pcscContext := &fakePCSCContext{cards: map[string]*fakePCSCCard{"Reader One": card}}
	factory := &fakePCSCFactory{contexts: []*fakePCSCContext{pcscContext}}

	backend, err := transportnfc.NewPCSCBackendWithFactory(factory.New)
	if err != nil {
		t.Fatalf("NewPCSCBackendWithFactory() error = %v", err)
	}

	session, err := backend.Open(context.Background(), transport.DeviceDescriptor{ID: "pcsc:Reader One", Path: "Reader One", Transport: transport.KindNFC})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	response, err := session.Exchange(context.Background(), []byte{0x01})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !bytes.Equal(response, []byte{0xAA}) {
		t.Fatalf("response = %x, want aa", response)
	}
	if !bytes.Equal(card.requests[0], fidoAppletSelect) {
		t.Fatalf("select APDU = %x, want %x", card.requests[0], fidoAppletSelect)
	}
	if len(card.requests) != 2 {
		t.Fatalf("len(requests) = %d, want 2", len(card.requests))
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !card.closed {
		t.Fatal("session close should close the card")
	}
	if !pcscContext.released {
		t.Fatal("session close should release the context")
	}
}

func TestPCSCBackendDiscoverReturnsDevicesAlongsideReaderProbeErrors(t *testing.T) {
	t.Parallel()

	readerOK := &fakePCSCCard{responses: [][]byte{{0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00}}}
	readerBroken := &fakePCSCCard{responses: [][]byte{{0x90}}}
	factory := &fakePCSCFactory{contexts: []*fakePCSCContext{{
		readers: []string{"Reader One", "Reader Broken"},
		cards: map[string]*fakePCSCCard{
			"Reader One":    readerOK,
			"Reader Broken": readerBroken,
		},
	}}}

	backend, err := transportnfc.NewPCSCBackendWithFactory(factory.New)
	if err != nil {
		t.Fatalf("NewPCSCBackendWithFactory() error = %v", err)
	}

	devices, err := backend.Discover(context.Background())
	if err == nil {
		t.Fatal("Discover() error = nil, want partial reader warning")
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].ID != "pcsc:Reader One" {
		t.Fatalf("device ID = %q", devices[0].ID)
	}
}
