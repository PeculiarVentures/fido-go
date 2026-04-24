package ctap2

import "github.com/PeculiarVentures/fido-go/pkg/protocol"

// CommandReset is the CTAP2 authenticatorReset command identifier.
const CommandReset byte = 0x07

// ResetResponse is the decoded response for authenticatorReset.
type ResetResponse struct{}

// ResetCommand implements authenticatorReset.
type ResetCommand struct{}

// NewResetCommand creates a Reset command instance.
func NewResetCommand() *ResetCommand {
	return &ResetCommand{}
}

// Protocol returns the CTAP2 protocol family.
func (command *ResetCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// Encode serializes the Reset command.
func (command *ResetCommand) Encode() ([]byte, error) {
	return encodeCommand(CommandReset, nil)
}

// DecodeResponse validates that the reset command completed successfully.
func (command *ResetCommand) DecodeResponse(data []byte, response any) error {
	_, err := DecodeInto[ResetResponse](response, "reset")
	if err != nil {
		return err
	}
	return decodeCommandResponse(data, nil)
}
