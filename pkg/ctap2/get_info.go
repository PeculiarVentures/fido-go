package ctap2

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Command is the CTAP2 command contract.
type Command interface {
	Protocol() protocol.Family
	Encode() ([]byte, error)
	DecodeResponse([]byte, any) error
}

// CommandGetInfo is the CTAP2 authenticatorGetInfo command identifier.
const CommandGetInfo byte = 0x04

// GetInfoResponse is the decoded response for authenticatorGetInfo.
type GetInfoResponse struct {
	Versions                 []string        `cbor:"1,keyasint"`
	Extensions               []string        `cbor:"2,keyasint,omitempty"`
	AAGUID                   []byte          `cbor:"3,keyasint"`
	Options                  map[string]bool `cbor:"4,keyasint,omitempty"`
	MaxMsgSize               uint64          `cbor:"5,keyasint,omitempty"`
	PinUVAuthProtocols       []uint64        `cbor:"6,keyasint,omitempty"`
	MaxCredentialCountInList uint64          `cbor:"7,keyasint,omitempty"`
	MaxCredentialIDLength    uint64          `cbor:"8,keyasint,omitempty"`
	Transports               []string        `cbor:"9,keyasint,omitempty"`
}

// GetInfoCommand implements authenticatorGetInfo.
type GetInfoCommand struct{}

// NewGetInfoCommand creates a GetInfo command instance.
func NewGetInfoCommand() *GetInfoCommand {
	return &GetInfoCommand{}
}

// Protocol returns the CTAP2 protocol family.
func (command *GetInfoCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// Encode serializes the command byte for authenticatorGetInfo.
func (command *GetInfoCommand) Encode() ([]byte, error) {
	return []byte{CommandGetInfo}, nil
}

// DecodeResponse parses the CTAP2 status byte and CBOR response payload.
func (command *GetInfoCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*GetInfoResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap2: get info response target must be *GetInfoResponse")
	}
	if len(data) == 0 {
		return fmt.Errorf("ctap2: response is empty")
	}
	if data[0] != 0x00 {
		return &Error{Code: data[0]}
	}
	if len(data) == 1 {
		return fmt.Errorf("ctap2: get info payload is empty")
	}

	if err := cbor.Unmarshal(data[1:], target); err != nil {
		return fmt.Errorf("ctap2: decode get info response: %w", err)
	}
	if len(target.Versions) == 0 {
		return fmt.Errorf("ctap2: get info response missing versions")
	}
	if len(target.AAGUID) != 16 {
		return fmt.Errorf("ctap2: get info response has invalid AAGUID length %d", len(target.AAGUID))
	}
	return nil
}
