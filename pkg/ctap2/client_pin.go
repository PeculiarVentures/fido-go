package ctap2

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CommandClientPIN is the CTAP2 authenticatorClientPIN command identifier.
const CommandClientPIN byte = 0x06

// ClientPINSubcommand identifies one ClientPIN subcommand.
type ClientPINSubcommand uint64

const (
	// ClientPINGetRetries requests the remaining PIN retries.
	ClientPINGetRetries ClientPINSubcommand = 0x01
	// ClientPINGetKeyAgreement requests the authenticator key agreement key.
	ClientPINGetKeyAgreement ClientPINSubcommand = 0x02
	// ClientPINSetPIN sets a new PIN.
	ClientPINSetPIN ClientPINSubcommand = 0x03
	// ClientPINChangePIN changes an existing PIN.
	ClientPINChangePIN ClientPINSubcommand = 0x04
	// ClientPINGetPINToken requests a legacy pinUvAuthToken.
	ClientPINGetPINToken ClientPINSubcommand = 0x05
	// ClientPINGetPINTokenWithUV requests a pinUvAuthToken using built-in UV.
	ClientPINGetPINTokenWithUV ClientPINSubcommand = 0x06
	// ClientPINGetUVRetries requests the remaining UV retries.
	ClientPINGetUVRetries ClientPINSubcommand = 0x07
	// ClientPINGetPINTokenWithPIN requests a pinUvAuthToken using the PIN and permissions.
	ClientPINGetPINTokenWithPIN ClientPINSubcommand = 0x09
)

// ClientPINCommand implements authenticatorClientPIN foundations.
type ClientPINCommand struct {
	PinUVAuthProtocol uint64
	Subcommand        ClientPINSubcommand
	KeyAgreement      *COSEKey
	PinUVAuthParam    []byte
	NewPINEnc         []byte
	PINHashEnc        []byte
	Permissions       Permission
	PermissionsRPID   string
}

type clientPINRequest struct {
	PinUVAuthProtocol uint64              `cbor:"1,keyasint,omitempty"`
	Subcommand        ClientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement      *COSEKey            `cbor:"3,keyasint,omitempty"`
	PinUVAuthParam    []byte              `cbor:"4,keyasint,omitempty"`
	NewPINEnc         []byte              `cbor:"5,keyasint,omitempty"`
	PINHashEnc        []byte              `cbor:"6,keyasint,omitempty"`
	Permissions       Permission          `cbor:"9,keyasint,omitempty"`
	PermissionsRPID   string              `cbor:"10,keyasint,omitempty"`
}

// ClientPINResponse is the decoded response for authenticatorClientPIN.
type ClientPINResponse struct {
	KeyAgreement    *COSEKey `cbor:"1,keyasint,omitempty"`
	PinUVAuthToken  []byte   `cbor:"2,keyasint,omitempty"`
	PINRetries      uint64   `cbor:"3,keyasint,omitempty"`
	PowerCycleState bool     `cbor:"4,keyasint,omitempty"`
	UVRetries       uint64   `cbor:"5,keyasint,omitempty"`
}

// NewClientPINCommand creates a ClientPIN command instance.
func NewClientPINCommand(protocolVersion uint64, subcommand ClientPINSubcommand) *ClientPINCommand {
	return &ClientPINCommand{PinUVAuthProtocol: protocolVersion, Subcommand: subcommand}
}

// NewClientPINGetRetriesCommand creates a getRetries ClientPIN command.
func NewClientPINGetRetriesCommand(protocolVersion uint64) *ClientPINCommand {
	return NewClientPINCommand(protocolVersion, ClientPINGetRetries)
}

// Protocol returns the CTAP2 protocol family.
func (command *ClientPINCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// Encode serializes the ClientPIN request.
func (command *ClientPINCommand) Encode() ([]byte, error) {
	if command.Subcommand == 0 {
		return nil, fmt.Errorf("ctap2: client PIN subcommand is required")
	}
	if command.KeyAgreement != nil {
		if err := command.KeyAgreement.ValidateEC2(); err != nil {
			return nil, fmt.Errorf("ctap2: client PIN key agreement: %w", err)
		}
	}

	request := clientPINRequest{
		PinUVAuthProtocol: command.PinUVAuthProtocol,
		Subcommand:        command.Subcommand,
		KeyAgreement:      command.KeyAgreement.Clone(),
		PinUVAuthParam:    append([]byte(nil), command.PinUVAuthParam...),
		NewPINEnc:         append([]byte(nil), command.NewPINEnc...),
		PINHashEnc:        append([]byte(nil), command.PINHashEnc...),
		Permissions:       command.Permissions,
		PermissionsRPID:   command.PermissionsRPID,
	}
	return encodeCommand(CommandClientPIN, request)
}

// DecodeResponse parses the ClientPIN response structure.
func (command *ClientPINCommand) DecodeResponse(data []byte, response any) error {
	target, err := DecodeInto[ClientPINResponse](response, "client PIN")
	if err != nil {
		return err
	}
	if err := decodeCommandResponse(data, target); err != nil {
		return err
	}
	if target.KeyAgreement != nil {
		if err := target.KeyAgreement.ValidateEC2(); err != nil {
			return fmt.Errorf("ctap2: decode client PIN response: %w", err)
		}
	}
	return nil
}
