package client_test

import (
	"context"
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"testing"
)

type contextCloseSession struct {
	*mockSession
	got context.Context
	err error
}

func (s *contextCloseSession) CloseContext(ctx context.Context) error { s.got = ctx; return s.err }
func TestClientCloseContextForwardsToSession(t *testing.T) {
	failure := errors.New("cleanup pending")
	session := &contextCloseSession{mockSession: &mockSession{}, err: failure}
	sdk, err := client.New(session)
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := sdk.(client.ContextCloser)
	if !ok {
		t.Fatal("client lacks ContextCloser")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := closer.CloseContext(ctx); !errors.Is(err, failure) || session.got != ctx {
		t.Fatalf("close=%v context forwarded=%v", err, session.got == ctx)
	}
}
func TestClientCloseContextLegacySessionUnsupported(t *testing.T) {
	sdk, err := client.New(&mockSession{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sdk.(client.ContextCloser).CloseContext(context.Background()); !errors.Is(err, transport.ErrUnsupported) {
		t.Fatalf("legacy close=%v", err)
	}
}
