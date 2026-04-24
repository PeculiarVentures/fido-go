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
	Versions                         []string                   `cbor:"1,keyasint"`
	Extensions                       []string                   `cbor:"2,keyasint,omitempty"`
	AAGUID                           []byte                     `cbor:"3,keyasint"`
	Options                          map[string]bool            `cbor:"4,keyasint,omitempty"`
	MaxMsgSize                       uint64                     `cbor:"5,keyasint,omitempty"`
	PinUVAuthProtocols               []uint64                   `cbor:"6,keyasint,omitempty"`
	MaxCredentialCountInList         uint64                     `cbor:"7,keyasint,omitempty"`
	MaxCredentialIDLength            uint64                     `cbor:"8,keyasint,omitempty"`
	Transports                       []string                   `cbor:"9,keyasint,omitempty"`
	Algorithms                       []CredentialParameter      `cbor:"10,keyasint,omitempty"`
	MaxSerializedLargeBlobArray      uint64                     `cbor:"11,keyasint,omitempty"`
	ForcePINChange                   bool                       `cbor:"12,keyasint,omitempty"`
	MinPINLength                     uint64                     `cbor:"13,keyasint,omitempty"`
	FirmwareVersion                  uint64                     `cbor:"14,keyasint,omitempty"`
	MaxCredBlobLength                uint64                     `cbor:"15,keyasint,omitempty"`
	MaxRPIDsForSetMinPINLength       uint64                     `cbor:"16,keyasint,omitempty"`
	PreferredPlatformUVAttempts      uint64                     `cbor:"17,keyasint,omitempty"`
	UVModality                       uint64                     `cbor:"18,keyasint,omitempty"`
	Certifications                   map[string]uint64          `cbor:"19,keyasint,omitempty"`
	RemainingDiscoverableCredentials uint64                     `cbor:"20,keyasint,omitempty"`
	VendorPrototypeConfigCommands    []uint64                   `cbor:"21,keyasint,omitempty"`
	Raw                              map[uint64]cbor.RawMessage `cbor:"-"`
}

type getInfoResponseWire struct {
	Versions                         []string              `cbor:"1,keyasint"`
	Extensions                       []string              `cbor:"2,keyasint,omitempty"`
	AAGUID                           []byte                `cbor:"3,keyasint"`
	Options                          map[string]bool       `cbor:"4,keyasint,omitempty"`
	MaxMsgSize                       uint64                `cbor:"5,keyasint,omitempty"`
	PinUVAuthProtocols               []uint64              `cbor:"6,keyasint,omitempty"`
	MaxCredentialCountInList         uint64                `cbor:"7,keyasint,omitempty"`
	MaxCredentialIDLength            uint64                `cbor:"8,keyasint,omitempty"`
	Transports                       []string              `cbor:"9,keyasint,omitempty"`
	Algorithms                       []CredentialParameter `cbor:"10,keyasint,omitempty"`
	MaxSerializedLargeBlobArray      uint64                `cbor:"11,keyasint,omitempty"`
	ForcePINChange                   bool                  `cbor:"12,keyasint,omitempty"`
	MinPINLength                     uint64                `cbor:"13,keyasint,omitempty"`
	FirmwareVersion                  uint64                `cbor:"14,keyasint,omitempty"`
	MaxCredBlobLength                uint64                `cbor:"15,keyasint,omitempty"`
	MaxRPIDsForSetMinPINLength       uint64                `cbor:"16,keyasint,omitempty"`
	PreferredPlatformUVAttempts      uint64                `cbor:"17,keyasint,omitempty"`
	UVModality                       uint64                `cbor:"18,keyasint,omitempty"`
	Certifications                   map[string]uint64     `cbor:"19,keyasint,omitempty"`
	RemainingDiscoverableCredentials uint64                `cbor:"20,keyasint,omitempty"`
	VendorPrototypeConfigCommands    []uint64              `cbor:"21,keyasint,omitempty"`
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
	target, err := DecodeInto[GetInfoResponse](response, "get info")
	if err != nil {
		return err
	}
	if err := decodeCommandResponse(data, target); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	return nil
}

// Clone returns a defensive copy of the authenticatorGetInfo response.
func (response *GetInfoResponse) Clone() *GetInfoResponse {
	if response == nil {
		return nil
	}
	clone := *response
	clone.Versions = append([]string(nil), response.Versions...)
	clone.Extensions = append([]string(nil), response.Extensions...)
	clone.AAGUID = append([]byte(nil), response.AAGUID...)
	if response.Options != nil {
		clone.Options = make(map[string]bool, len(response.Options))
		for key, value := range response.Options {
			clone.Options[key] = value
		}
	}
	clone.PinUVAuthProtocols = append([]uint64(nil), response.PinUVAuthProtocols...)
	clone.Transports = append([]string(nil), response.Transports...)
	clone.Algorithms = append([]CredentialParameter(nil), response.Algorithms...)
	if response.Certifications != nil {
		clone.Certifications = make(map[string]uint64, len(response.Certifications))
		for key, value := range response.Certifications {
			clone.Certifications[key] = value
		}
	}
	clone.VendorPrototypeConfigCommands = append([]uint64(nil), response.VendorPrototypeConfigCommands...)
	clone.Raw = cloneRawCBORMap(response.Raw)
	return &clone
}

// Validate reports whether the decoded authenticatorGetInfo response satisfies the base CTAP invariants.
func (response *GetInfoResponse) Validate() error {
	if len(response.Versions) == 0 {
		return fmt.Errorf("ctap2: get info response missing versions")
	}
	if len(response.AAGUID) != 16 {
		return fmt.Errorf("ctap2: get info response has invalid AAGUID length %d", len(response.AAGUID))
	}
	if _, ok := response.Raw[0x06]; ok && len(response.PinUVAuthProtocols) == 0 {
		return fmt.Errorf("ctap2: get info response pinUvAuthProtocols must not be empty")
	}
	if _, ok := response.Raw[0x09]; ok && len(response.Transports) == 0 {
		return fmt.Errorf("ctap2: get info response transports must not be empty")
	}
	if _, ok := response.Raw[0x0A]; ok && len(response.Algorithms) == 0 {
		return fmt.Errorf("ctap2: get info response algorithms must not be empty")
	}
	return nil
}

// UnmarshalCBOR decodes a GetInfo response while preserving the raw response map for unknown fields.
func (response *GetInfoResponse) UnmarshalCBOR(data []byte) error {
	var wire getInfoResponseWire
	if err := cbor.Unmarshal(data, &wire); err != nil {
		return err
	}
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	*response = GetInfoResponse{
		Versions:                         wire.Versions,
		Extensions:                       wire.Extensions,
		AAGUID:                           wire.AAGUID,
		Options:                          wire.Options,
		MaxMsgSize:                       wire.MaxMsgSize,
		PinUVAuthProtocols:               wire.PinUVAuthProtocols,
		MaxCredentialCountInList:         wire.MaxCredentialCountInList,
		MaxCredentialIDLength:            wire.MaxCredentialIDLength,
		Transports:                       wire.Transports,
		Algorithms:                       wire.Algorithms,
		MaxSerializedLargeBlobArray:      wire.MaxSerializedLargeBlobArray,
		ForcePINChange:                   wire.ForcePINChange,
		MinPINLength:                     wire.MinPINLength,
		FirmwareVersion:                  wire.FirmwareVersion,
		MaxCredBlobLength:                wire.MaxCredBlobLength,
		MaxRPIDsForSetMinPINLength:       wire.MaxRPIDsForSetMinPINLength,
		PreferredPlatformUVAttempts:      wire.PreferredPlatformUVAttempts,
		UVModality:                       wire.UVModality,
		Certifications:                   wire.Certifications,
		RemainingDiscoverableCredentials: wire.RemainingDiscoverableCredentials,
		VendorPrototypeConfigCommands:    wire.VendorPrototypeConfigCommands,
		Raw:                              cloneRawCBORMap(raw),
	}
	return nil
}

func cloneRawCBORMap(raw map[uint64]cbor.RawMessage) map[uint64]cbor.RawMessage {
	if raw == nil {
		return nil
	}
	clone := make(map[uint64]cbor.RawMessage, len(raw))
	for key, value := range raw {
		clone[key] = append(cbor.RawMessage(nil), value...)
	}
	return clone
}
