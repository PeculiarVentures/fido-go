package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// RegisterRequest describes the basic fields required for credential creation.
type RegisterRequest struct {
	ChallengeHash        []byte
	RPID                 string
	RPName               string
	UserID               []byte
	UserName             string
	UserDisplayName      string
	CredentialParameters []ctap2.CredentialParameter
	ExcludeList          []ctap2.CredentialDescriptor
	Options              *ctap2.MakeCredentialOptions
	AppIDHash            []byte
}

// RegistrationResult contains the decoded response for the protocol that completed registration.
type RegistrationResult struct {
	Protocol ProtocolFamily
	CTAP1    *ctap1.RegisterResponse
	CTAP2    *ctap2.MakeCredentialResponse
}

// Register performs a basic credential creation flow using the best available protocol.
func (client *client) Register(ctx context.Context, request RegisterRequest) (*RegistrationResult, error) {
	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}

	if caps.HasCTAP2() {
		command := ctap2.NewMakeCredentialCommand(
			request.ChallengeHash,
			ctap2.RelyingPartyEntity{ID: request.RPID, Name: request.RPName},
			ctap2.UserEntity{ID: append([]byte(nil), request.UserID...), Name: request.UserName, DisplayName: request.UserDisplayName},
			defaultCredentialParameters(request.CredentialParameters),
		)
		command.ExcludeList = append([]ctap2.CredentialDescriptor(nil), request.ExcludeList...)
		command.Options = request.Options

		encoded, err := command.Encode()
		if err != nil {
			return nil, err
		}
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandMakeCredential, encoded[1:])
		if err != nil {
			return nil, err
		}
		var response ctap2.MakeCredentialResponse
		if err := command.DecodeResponse(responseBytes, &response); err != nil {
			return nil, err
		}
		return &RegistrationResult{Protocol: FamilyCTAP2, CTAP2: &response}, nil
	}

	if !caps.HasCTAP1() {
		return nil, ErrNoCapableProtocol
	}
	if len(request.ChallengeHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 register challenge hash must be 32 bytes")
	}
	if len(request.AppIDHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 register app id hash must be 32 bytes")
	}

	payload := append(append([]byte(nil), request.ChallengeHash...), request.AppIDHash...)
	command := ctap1.NewRegisterCommand(request.ChallengeHash, request.AppIDHash)
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandRegister, payload)
	if err != nil {
		return nil, err
	}
	var response ctap1.RegisterResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &RegistrationResult{Protocol: FamilyCTAP1, CTAP1: &response}, nil
}

func defaultCredentialParameters(parameters []ctap2.CredentialParameter) []ctap2.CredentialParameter {
	if len(parameters) == 0 {
		return []ctap2.CredentialParameter{{Type: "public-key", Alg: -7}}
	}
	result := make([]ctap2.CredentialParameter, len(parameters))
	copy(result, parameters)
	return result
}
