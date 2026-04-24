package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// Authenticate performs a basic assertion flow using the best available protocol.
func (client *client) Authenticate(ctx context.Context, request AuthenticationRequest) (*AuthenticationResult, error) {
	caps, err := client.Capabilities(ctx)
	if err != nil {
		return nil, err
	}

	if caps.HasCTAP2() {
		info := caps.RawCTAP2
		useBuiltInUV, pinUVAuthParam, pinUVAuthProtocol, err := client.resolveCTAP2UserVerification(
			ctx,
			info,
			"authenticate",
			request.Selection,
			request.ChallengeHash,
			ctap2.PermissionGetAssertion,
			request.RPID,
		)
		if err != nil {
			return nil, err
		}
		client.emitInteraction(ctx, InteractionEvent{
			Kind:      InteractionAwaitingUserPresence,
			Operation: "authenticate",
			Protocol:  FamilyCTAP2,
			Message:   "Touch or tap the authenticator to continue authentication.",
			Retryable: true,
		})
		command := ctap2.NewGetAssertionCommand(request.RPID, request.ChallengeHash)
		command.AllowList = credentialDescriptorsToCTAP2(authenticationAllowList(request.CTAP2))
		command.Options = getAssertionOptions(request.Selection, useBuiltInUV)
		command.PinUVAuthProtocol = pinUVAuthProtocol
		command.PinUVAuthParam = pinUVAuthParam

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
		parsedAuthData, err := parseAuthenticatorData(response.AuthData)
		if err != nil {
			return nil, err
		}
		return &AuthenticationResult{
			Protocol:     FamilyCTAP2,
			CredentialID: append([]byte(nil), response.Credential.ID...),
			Signature:    append([]byte(nil), response.Signature...),
			SignCount:    parsedAuthData.SignCount,
			UserPresent:  parsedAuthData.UserPresent,
			UserVerified: parsedAuthData.UserVerified,
			RawCTAP2:     &response,
		}, nil
	}

	if !caps.HasCTAP1() {
		return nil, ErrNoCapableProtocol
	}
	if request.CTAP1 == nil {
		return nil, fmt.Errorf("client: ctap1 authentication requires ctap1 options")
	}
	if len(request.ChallengeHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 authenticate challenge hash must be 32 bytes")
	}
	if len(request.CTAP1.AppIDHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 authenticate app id hash must be 32 bytes")
	}
	if len(request.CTAP1.KeyHandle) == 0 {
		return nil, fmt.Errorf("client: ctap1 authenticate key handle must not be empty")
	}

	client.emitInteraction(ctx, InteractionEvent{
		Kind:      InteractionAwaitingUserPresence,
		Operation: "authenticate",
		Protocol:  FamilyCTAP1,
		Message:   "Touch or tap the authenticator to continue authentication.",
		Retryable: true,
	})
	control := request.CTAP1.Control
	if control == 0 {
		control = defaultCTAP1AuthenticateControl(request.Selection)
	}
	payload := make([]byte, 0, 65+len(request.CTAP1.KeyHandle))
	payload = append(payload, request.ChallengeHash...)
	payload = append(payload, request.CTAP1.AppIDHash...)
	payload = append(payload, byte(len(request.CTAP1.KeyHandle)))
	payload = append(payload, request.CTAP1.KeyHandle...)

	command := ctap1.NewAuthenticateCommand(control, request.ChallengeHash, request.CTAP1.AppIDHash, request.CTAP1.KeyHandle)
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandAuthenticate, payload)
	if err != nil {
		return nil, err
	}
	var response ctap1.AuthenticateResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &AuthenticationResult{
		Protocol:     FamilyCTAP1,
		CredentialID: append([]byte(nil), request.CTAP1.KeyHandle...),
		Signature:    append([]byte(nil), response.Signature...),
		SignCount:    response.Counter,
		UserPresent:  response.UserPresent(),
		UserVerified: false,
		RawCTAP1:     &response,
	}, nil
}

func authenticationAllowList(options *CTAP2AuthenticationOptions) []CredentialDescriptor {
	if options == nil {
		return nil
	}
	return options.AllowList
}

func makeCredentialOptions(selection AuthenticatorSelection, useBuiltInUV bool, registration *CTAP2RegistrationOptions) *ctap2.MakeCredentialOptions {
	options := &ctap2.MakeCredentialOptions{}
	if registrationResidentKey(registration) {
		options.ResidentKey = true
	}
	if selection.normalizedUserPresence() == RequirementRequired {
		options.UserPresence = true
	}
	if useBuiltInUV {
		options.UserVerification = true
	}
	if !options.ResidentKey && !options.UserPresence && !options.UserVerification {
		return nil
	}
	return options
}

func getAssertionOptions(selection AuthenticatorSelection, useBuiltInUV bool) *ctap2.GetAssertionOptions {
	options := &ctap2.GetAssertionOptions{}
	if selection.normalizedUserPresence() == RequirementRequired {
		options.UserPresence = true
	}
	if useBuiltInUV {
		options.UserVerification = true
	}
	if !options.UserPresence && !options.UserVerification {
		return nil
	}
	return options
}
