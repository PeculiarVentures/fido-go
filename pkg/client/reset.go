package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// Reset performs a basic CTAP2 authenticator reset.
func (client *client) Reset(ctx context.Context) error {
	caps, err := client.Capabilities(ctx)
	if err != nil {
		return err
	}
	if !caps.HasCTAP2() {
		if caps.HasCTAP1() {
			return fmt.Errorf("client: authenticator supports CTAP1 only; reset requires CTAP2")
		}
		return ErrNoCapableProtocol
	}
	client.emitInteraction(ctx, InteractionEvent{
		Kind:      InteractionAwaitingUserPresence,
		Operation: "reset",
		Protocol:  FamilyCTAP2,
		Message:   "Touch or tap the authenticator to confirm reset.",
		Retryable: true,
	})

	command := ctap2.NewResetCommand()
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandReset, nil)
	if err != nil {
		return err
	}
	var response ctap2.ResetResponse
	return command.DecodeResponse(responseBytes, &response)
}
