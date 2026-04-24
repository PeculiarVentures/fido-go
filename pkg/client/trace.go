package client

import (
	"context"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
)

const (
	ctap2CommandClientPIN                   byte = 0x06
	ctap2CommandCredentialManagement        byte = 0x0a
	ctap2CommandCredentialManagementPreview byte = 0x41
)

// TraceDirection identifies whether a recorded payload was outbound or inbound.
type TraceDirection string

const (
	// TraceDirectionRequest marks outbound transport payloads.
	TraceDirectionRequest TraceDirection = "request"
	// TraceDirectionResponse marks inbound transport payloads.
	TraceDirectionResponse TraceDirection = "response"
)

// TraceEvent captures one exchanged payload for diagnostics.
type TraceEvent struct {
	Direction TraceDirection `json:"direction"`
	Payload   []byte         `json:"payload"`
	Redacted  bool           `json:"redacted,omitempty"`
	Command   byte           `json:"command,omitempty"`
	Length    int            `json:"length,omitempty"`
}

// TraceRecorder stores payload traces captured through client middleware.
type TraceRecorder struct {
	mu     sync.Mutex
	events []TraceEvent
}

type traceMiddleware struct {
	recorder      *TraceRecorder
	redactSecrets bool
}

// TraceOptions configures payload tracing.
type TraceOptions struct {
	// RedactSecrets hides CTAP payloads likely to contain PIN, pinUvAuthToken,
	// credential-management, or other sensitive authenticator material.
	RedactSecrets bool
}

// NewTraceRecorder creates a trace recorder for CLI and debugging flows.
func NewTraceRecorder() *TraceRecorder {
	return &TraceRecorder{}
}

// Events returns a stable copy of the recorded trace events.
func (recorder *TraceRecorder) Events() []TraceEvent {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	events := make([]TraceEvent, len(recorder.events))
	for index, event := range recorder.events {
		events[index] = TraceEvent{
			Direction: event.Direction,
			Payload:   append([]byte(nil), event.Payload...),
			Redacted:  event.Redacted,
			Command:   event.Command,
			Length:    event.Length,
		}
	}
	return events
}

// WithTrace records raw request and response metadata through the client middleware chain.
//
// Sensitive CTAP2 commands are redacted by default. Pass
// TraceOptions{RedactSecrets:false} only for deliberate low-level debugging.
func WithTrace(recorder *TraceRecorder, options ...TraceOptions) Option {
	return func(cfg *config) error {
		if recorder == nil {
			return ErrTraceRecorderRequired
		}
		traceOptions := TraceOptions{RedactSecrets: true}
		if len(options) > 0 {
			traceOptions = options[0]
		}
		cfg.middlewares = append(cfg.middlewares, traceMiddleware{recorder: recorder, redactSecrets: traceOptions.RedactSecrets})
		return nil
	}
}

func (wrapper traceMiddleware) WrapExchange(next middleware.ExchangeFunc) middleware.ExchangeFunc {
	return func(ctx context.Context, req []byte) ([]byte, error) {
		command := traceCommand(req)
		redact := wrapper.redactSecrets && traceCommandContainsSecrets(command)
		wrapper.recorder.record(TraceDirectionRequest, req, command, redact)
		response, err := next(ctx, req)
		if len(response) != 0 {
			wrapper.recorder.record(TraceDirectionResponse, response, command, redact)
		}
		return response, err
	}
}

func (recorder *TraceRecorder) record(direction TraceDirection, payload []byte, command byte, redacted bool) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	event := TraceEvent{Direction: direction, Command: command, Length: len(payload), Redacted: redacted}
	if !redacted {
		event.Payload = append([]byte(nil), payload...)
	}
	recorder.events = append(recorder.events, event)
}

func traceCommand(payload []byte) byte {
	if len(payload) == 0 {
		return 0
	}
	return payload[0]
}

func traceCommandContainsSecrets(command byte) bool {
	switch command {
	case ctap2CommandClientPIN, ctap2CommandCredentialManagement, ctap2CommandCredentialManagementPreview:
		return true
	default:
		return false
	}
}
