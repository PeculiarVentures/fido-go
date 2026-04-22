package ctap1

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// Command is the CTAP1 command contract.
type Command interface {
	Protocol() protocol.Family
	Encode() ([]byte, error)
	DecodeResponse([]byte, any) error
}

// CommandVersion is the CTAP1 Version command identifier.
const CommandVersion byte = 0x03

// VersionResponse is the decoded response for U2F_VERSION.
type VersionResponse struct {
	Version string
}

// VersionCommand implements the U2F_VERSION command.
type VersionCommand struct{}

// NewVersionCommand creates a Version command instance.
func NewVersionCommand() *VersionCommand {
	return &VersionCommand{}
}

// Protocol returns the CTAP1 protocol family.
func (command *VersionCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP1
}

// Encode serializes the Version command using the short APDU form from the U2F 1.2 spec.
func (command *VersionCommand) Encode() ([]byte, error) {
	return EncodeShortAPDU(CommandVersion, nil)
}

// DecodeResponse parses the APDU response and extracts the ASCII version string.
func (command *VersionCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*VersionResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap1: version response target must be *VersionResponse")
	}

	payload, _, err := decodeResponse(data)
	if err != nil {
		return err
	}

	target.Version = string(payload)
	return nil
}
