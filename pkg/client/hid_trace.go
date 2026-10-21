package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/middleware"
)

// HIDTraceEvent records an explicit CTAPHID payload separately from CTAP traces.
type HIDTraceEvent struct {
	Direction TraceDirection `json:"direction"`
	Command   byte           `json:"command"`
	Payload   []byte         `json:"payload"`
	Redacted  bool           `json:"redacted,omitempty"`
	Length    int            `json:"length"`
}

// HIDEvents returns a defensive copy of explicit CTAPHID trace events.
// Command is the logical HID command, even when the payload is empty.
// Events continues to return only traces from ordinary CTAP exchanges.
func (recorder *TraceRecorder) HIDEvents() []HIDTraceEvent {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	events := make([]HIDTraceEvent, len(recorder.hidEvents))
	for index, event := range recorder.hidEvents {
		events[index] = event
		events[index].Payload = append([]byte(nil), event.Payload...)
	}
	return events
}

func (wrapper traceMiddleware) WrapHIDExchange(next middleware.HIDExchangeFunc) middleware.HIDExchangeFunc {
	return func(ctx context.Context, command byte, payload []byte) ([]byte, error) {
		// Vendor payload semantics are unknown, so redact the entire message.
		wrapper.recorder.recordHID(TraceDirectionRequest, command, payload, wrapper.redactSecrets)
		response, err := next(ctx, command, payload)
		if err == nil || len(response) != 0 {
			wrapper.recorder.recordHID(TraceDirectionResponse, command, response, wrapper.redactSecrets)
		}
		return response, err
	}
}

func (recorder *TraceRecorder) recordHID(direction TraceDirection, command byte, payload []byte, redacted bool) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	event := HIDTraceEvent{Direction: direction, Command: command, Length: len(payload), Redacted: redacted}
	if !redacted {
		event.Payload = append([]byte(nil), payload...)
	}
	recorder.hidEvents = append(recorder.hidEvents, event)
}
