package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// InteractionHandler receives user-interaction events and PIN prompts.
type InteractionHandler interface {
	OnInteraction(ctx context.Context, event InteractionEvent)
	RequestPIN(ctx context.Context, req PINRequest) (string, error)
}

// InteractionEvent describes one authenticator interaction requirement.
type InteractionEvent struct {
	Kind      InteractionKind `json:"kind"`
	Operation string          `json:"operation,omitempty"`
	Protocol  ProtocolFamily  `json:"protocol,omitempty"`
	Transport transport.Kind  `json:"transport,omitempty"`
	Message   string          `json:"message,omitempty"`
	Retryable bool            `json:"retryable,omitempty"`
}

// InteractionKind identifies the current interaction state.
type InteractionKind string

const (
	// InteractionAwaitingUserPresence reports that the authenticator is waiting for user presence.
	InteractionAwaitingUserPresence InteractionKind = "awaiting-user-presence"
	// InteractionAwaitingUserVerification reports that the authenticator is waiting for user verification.
	InteractionAwaitingUserVerification InteractionKind = "awaiting-user-verification"
	// InteractionAwaitingPIN reports that the platform needs a PIN value.
	InteractionAwaitingPIN InteractionKind = "awaiting-pin"
	// InteractionProcessing reports that an authenticator command is in progress.
	InteractionProcessing InteractionKind = "processing"
	// InteractionReinsertRequired reports that the authenticator must be reinserted or tapped again.
	InteractionReinsertRequired InteractionKind = "reinsert-required"
)

// PINRequest describes one PIN prompt initiated by the SDK.
type PINRequest struct {
	Operation string             `json:"operation,omitempty"`
	Protocol  ProtocolFamily     `json:"protocol,omitempty"`
	Transport transport.Kind     `json:"transport,omitempty"`
	Method    VerificationMethod `json:"method,omitempty"`
	Message   string             `json:"message,omitempty"`
}

func (client *client) emitInteraction(ctx context.Context, event InteractionEvent) {
	if client == nil || client.interaction == nil {
		return
	}
	if event.Transport == "" && client.session != nil {
		event.Transport = client.session.Device().Transport
	}
	client.interaction.OnInteraction(ctx, event)
}

func (client *client) requestPIN(ctx context.Context, req PINRequest) (string, error) {
	if client == nil || client.interaction == nil {
		return "", ErrPINRequired
	}
	if req.Transport == "" && client.session != nil {
		req.Transport = client.session.Device().Transport
	}
	if req.Message == "" {
		req.Message = "Enter authenticator PIN"
	}
	client.emitInteraction(ctx, InteractionEvent{
		Kind:      InteractionAwaitingPIN,
		Operation: req.Operation,
		Protocol:  req.Protocol,
		Transport: req.Transport,
		Message:   req.Message,
		Retryable: true,
	})
	return client.interaction.RequestPIN(ctx, req)
}
