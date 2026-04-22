package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// AuthenticateRequest describes the basic fields required for assertion flows.
type AuthenticateRequest struct {
	ChallengeHash []byte
	RPID          string
	AllowList     []ctap2.CredentialDescriptor
	Options       *ctap2.GetAssertionOptions
	AppIDHash     []byte
	KeyHandle     []byte
	Control       ctap1.Control
}

// AssertionResult contains the decoded response for the protocol that completed authentication.
type AssertionResult struct {
	Protocol ProtocolFamily
	CTAP1    *ctap1.AuthenticateResponse
	CTAP2    *ctap2.GetAssertionResponse
}

// Authenticate performs a basic assertion flow using the best available protocol.
func (client *client) Authenticate(ctx context.Context, request AuthenticateRequest) (*AssertionResult, error) {
	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}

	if caps.HasCTAP2() {
		command := ctap2.NewGetAssertionCommand(request.RPID, request.ChallengeHash)
		command.AllowList = append([]ctap2.CredentialDescriptor(nil), request.AllowList...)
		command.Options = request.Options

		encoded, err := command.Encode()
		if err != nil {
			return nil, err
		}
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandGetAssertion, encoded[1:])
		if err != nil {
			return nil, err
		}
		var response ctap2.GetAssertionResponse
		if err := command.DecodeResponse(responseBytes, &response); err != nil {
			return nil, err
		}
		return &AssertionResult{Protocol: FamilyCTAP2, CTAP2: &response}, nil
	}

	if !caps.HasCTAP1() {
		return nil, ErrNoCapableProtocol
	}
	if len(request.ChallengeHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 authenticate challenge hash must be 32 bytes")
	}
	if len(request.AppIDHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 authenticate app id hash must be 32 bytes")
	}
	if len(request.KeyHandle) == 0 {
		return nil, fmt.Errorf("client: ctap1 authenticate key handle must not be empty")
	}

	control := request.Control
	if control == 0 {
		control = ctap1.ControlEnforceUserPresenceAndSign
	}
	payload := make([]byte, 0, 65+len(request.KeyHandle))
	payload = append(payload, request.ChallengeHash...)
	payload = append(payload, request.AppIDHash...)
	payload = append(payload, byte(len(request.KeyHandle)))
	payload = append(payload, request.KeyHandle...)

	command := ctap1.NewAuthenticateCommand(control, request.ChallengeHash, request.AppIDHash, request.KeyHandle)
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandAuthenticate, payload)
	if err != nil {
		return nil, err
	}
	var response ctap1.AuthenticateResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &AssertionResult{Protocol: FamilyCTAP1, CTAP1: &response}, nil
}
