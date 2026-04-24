package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// Register performs a basic credential creation flow using the best available protocol.
func (client *client) Register(ctx context.Context, request RegistrationRequest) (*RegistrationResult, error) {
	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}

	if caps.HasCTAP2() {
		info := caps.RawCTAP2
		useBuiltInUV, pinUVAuthParam, pinUVAuthProtocol, err := client.resolveCTAP2UserVerification(
			ctx,
			info,
			"register",
			request.Selection,
			request.ChallengeHash,
			ctap2.PermissionMakeCredential,
			request.RPID,
		)
		if err != nil {
			return nil, err
		}
		client.emitInteraction(ctx, InteractionEvent{
			Kind:      InteractionAwaitingUserPresence,
			Operation: "register",
			Protocol:  FamilyCTAP2,
			Message:   "Touch or tap the authenticator to continue registration.",
			Retryable: true,
		})
		ctap2Options := request.CTAP2
		command := ctap2.NewMakeCredentialCommand(
			request.ChallengeHash,
			ctap2.RelyingPartyEntity{ID: request.RPID, Name: registrationRPName(ctap2Options)},
			ctap2.UserEntity{ID: append([]byte(nil), request.User.ID...), Name: request.User.Name, DisplayName: request.User.DisplayName},
			defaultCredentialParameters(registrationCredentialParameters(ctap2Options)),
		)
		command.ExcludeList = append([]ctap2.CredentialDescriptor(nil), registrationExcludeList(ctap2Options)...)
		command.Options = makeCredentialOptions(request.Selection, useBuiltInUV, ctap2Options)
		command.PinUVAuthProtocol = pinUVAuthProtocol
		command.PinUVAuthParam = pinUVAuthParam

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
		parsedAuthData, err := parseAuthenticatorData(response.AuthData)
		if err != nil {
			return nil, err
		}
		if len(parsedAuthData.CredentialID) == 0 {
			return nil, fmt.Errorf("client: ctap2 registration response is missing credential id")
		}
		return &RegistrationResult{
			Protocol:          FamilyCTAP2,
			CredentialID:      parsedAuthData.CredentialID,
			AttestationFormat: response.Format,
			UserPresent:       parsedAuthData.UserPresent,
			UserVerified:      parsedAuthData.UserVerified,
			RawCTAP2:          &response,
		}, nil
	}

	if !caps.HasCTAP1() {
		return nil, ErrNoCapableProtocol
	}
	if request.CTAP1 == nil {
		return nil, fmt.Errorf("client: ctap1 registration requires ctap1 options")
	}
	if len(request.ChallengeHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 register challenge hash must be 32 bytes")
	}
	if len(request.CTAP1.AppIDHash) != 32 {
		return nil, fmt.Errorf("client: ctap1 register app id hash must be 32 bytes")
	}

	client.emitInteraction(ctx, InteractionEvent{
		Kind:      InteractionAwaitingUserPresence,
		Operation: "register",
		Protocol:  FamilyCTAP1,
		Message:   "Touch or tap the authenticator to continue registration.",
		Retryable: true,
	})
	payload := append(append([]byte(nil), request.ChallengeHash...), request.CTAP1.AppIDHash...)
	command := ctap1.NewRegisterCommand(request.ChallengeHash, request.CTAP1.AppIDHash)
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandRegister, payload)
	if err != nil {
		return nil, err
	}
	var response ctap1.RegisterResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &RegistrationResult{
		Protocol:          FamilyCTAP1,
		CredentialID:      append([]byte(nil), response.KeyHandle...),
		AttestationFormat: fidoU2FAttestationFormat,
		UserPresent:       true,
		UserVerified:      false,
		RawCTAP1:          &response,
	}, nil
}

func defaultCredentialParameters(parameters []ctap2.CredentialParameter) []ctap2.CredentialParameter {
	if len(parameters) == 0 {
		return []ctap2.CredentialParameter{{Type: "public-key", Alg: -7}}
	}
	result := make([]ctap2.CredentialParameter, len(parameters))
	copy(result, parameters)
	return result
}

func registrationRPName(options *CTAP2RegistrationOptions) string {
	if options == nil {
		return ""
	}
	return options.RPName
}

func registrationResidentKey(options *CTAP2RegistrationOptions) bool {
	if options == nil {
		return false
	}
	return options.ResidentKey
}

func registrationCredentialParameters(options *CTAP2RegistrationOptions) []ctap2.CredentialParameter {
	if options == nil {
		return nil
	}
	return options.CredentialParameters
}

func registrationExcludeList(options *CTAP2RegistrationOptions) []ctap2.CredentialDescriptor {
	if options == nil {
		return nil
	}
	return options.ExcludeList
}
