package client

import (
	"context"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
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
}

// TraceRecorder stores payload traces captured through client middleware.
type TraceRecorder struct {
	mu     sync.Mutex
	events []TraceEvent
}

type traceMiddleware struct {
	recorder *TraceRecorder
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
		}
	}
	return events
}

// WithTrace records raw request and response payloads through the client middleware chain.
func WithTrace(recorder *TraceRecorder) Option {
	return func(cfg *config) error {
		if recorder == nil {
			return ErrTraceRecorderRequired
		}
		cfg.middlewares = append(cfg.middlewares, traceMiddleware{recorder: recorder})
		return nil
	}
}

func (wrapper traceMiddleware) WrapExchange(next middleware.ExchangeFunc) middleware.ExchangeFunc {
	return func(ctx context.Context, req []byte) ([]byte, error) {
		wrapper.recorder.record(TraceDirectionRequest, req)
		response, err := next(ctx, req)
		if len(response) != 0 {
			wrapper.recorder.record(TraceDirectionResponse, response)
		}
		return response, err
	}
}

func (recorder *TraceRecorder) record(direction TraceDirection, payload []byte) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.events = append(recorder.events, TraceEvent{Direction: direction, Payload: append([]byte(nil), payload...)})
}
