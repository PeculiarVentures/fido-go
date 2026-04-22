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

	if len(data) < 2 {
		return fmt.Errorf("ctap1: response is too short")
	}

	statusWord := uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])
	if statusWord != successStatusWord {
		return &Error{StatusWord: statusWord}
	}

	target.Version = string(data[:len(data)-2])
	return nil
}

// EncodeShortAPDU encodes a CTAP1 command using the short APDU form.
func EncodeShortAPDU(command byte, data []byte) ([]byte, error) {
	if len(data) > 0xff {
		return nil, fmt.Errorf("ctap1: APDU payload exceeds short encoding limit: %d", len(data))
	}

	if len(data) == 0 {
		return []byte{0x00, command, 0x00, 0x00, 0x00}, nil
	}

	encoded := make([]byte, 0, 6+len(data))
	encoded = append(encoded, 0x00, command, 0x00, 0x00, byte(len(data)))
	encoded = append(encoded, data...)
	encoded = append(encoded, 0x00)
	return encoded, nil
}
