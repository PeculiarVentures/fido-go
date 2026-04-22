package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// Reset performs a basic CTAP2 authenticator reset.
func (client *client) Reset(ctx context.Context) error {
	command := ctap2.NewResetCommand()
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandReset, nil)
	if err != nil {
		return err
	}
	var response ctap2.ResetResponse
	return command.DecodeResponse(responseBytes, &response)
}
