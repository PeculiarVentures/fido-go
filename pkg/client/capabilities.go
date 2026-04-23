package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// CTAP1Capabilities describes the detected CTAP1 capability baseline.
type CTAP1Capabilities struct {
	Version string `json:"version,omitempty"`
}

// ProtocolCapabilities describes normalized protocol support for the selected authenticator.
type ProtocolCapabilities struct {
	CTAP1     bool           `json:"ctap1"`
	CTAP2     bool           `json:"ctap2"`
	Preferred ProtocolFamily `json:"preferred,omitempty"`
}

// AuthenticatorCapabilities describes normalized authenticator-management support.
type AuthenticatorCapabilities struct {
	ResidentKey                 bool `json:"residentKey,omitempty"`
	CredentialManagement        bool `json:"credentialManagement,omitempty"`
	CredentialManagementPreview bool `json:"credentialManagementPreview,omitempty"`
}

// VerificationMethod identifies one authenticator-side user-verification method.
type VerificationMethod string

const (
	// VerificationMethodPIN identifies ClientPIN verification.
	VerificationMethodPIN VerificationMethod = "pin"
	// VerificationMethodBuiltInUV identifies a built-in authenticator verifier.
	VerificationMethodBuiltInUV VerificationMethod = "built-in-uv"
)

// VerificationCapabilities describes normalized user-verification support.
type VerificationCapabilities struct {
	ClientPIN          bool `json:"clientPin,omitempty"`
	BuiltInUV          bool `json:"builtInUv,omitempty"`
	PinUVAuthToken     bool `json:"pinUvAuthToken,omitempty"`
	BioEnrollment      bool `json:"bioEnrollment,omitempty"`
	UVRetriesAvailable bool `json:"uvRetriesAvailable,omitempty"`
}

// InteractionCapabilities describes normalized interaction requirements.
type InteractionCapabilities struct {
	UserPresence        bool `json:"userPresence,omitempty"`
	UserVerification    bool `json:"userVerification,omitempty"`
	BuiltInUV           bool `json:"builtInUv,omitempty"`
	NFCImplicitPresence bool `json:"nfcImplicitPresence,omitempty"`
}

// Capabilities describes detected authenticator support in a stable public shape.
type Capabilities struct {
	Protocols     ProtocolCapabilities      `json:"protocols"`
	Authenticator AuthenticatorCapabilities `json:"authenticator"`
	Verification  VerificationCapabilities  `json:"verification"`
	Interaction   InteractionCapabilities   `json:"interaction"`

	RawCTAP1 *CTAP1Capabilities     `json:"rawCtap1,omitempty"`
	RawCTAP2 *ctap2.GetInfoResponse `json:"rawCtap2,omitempty"`

	// Deprecated: use RawCTAP1.
	CTAP1 *CTAP1Capabilities `json:"-"`
	// Deprecated: use RawCTAP2.
	CTAP2 *ctap2.GetInfoResponse `json:"-"`
}

// DeviceCapabilities aliases the normalized capabilities shape for compatibility.
type DeviceCapabilities = Capabilities

// PINRetries describes the authenticator retry counters reported by ClientPIN.
type PINRetries struct {
	PINRetries      uint64
	UVRetries       uint64
	PowerCycleState bool
}

// HasCTAP1 reports whether CTAP1 support has been detected.
func (caps *Capabilities) HasCTAP1() bool {
	return caps != nil && (caps.RawCTAP1 != nil || caps.CTAP1 != nil)
}

// HasCTAP2 reports whether CTAP2 support has been detected.
func (caps *Capabilities) HasCTAP2() bool {
	return caps != nil && (caps.RawCTAP2 != nil || caps.CTAP2 != nil)
}

// PreferredProtocol reports the highest-preference detected protocol family.
func (caps *Capabilities) PreferredProtocol() (protocol.Family, bool) {
	if caps.HasCTAP2() {
		return protocol.FamilyCTAP2, true
	}
	if caps.HasCTAP1() {
		return protocol.FamilyCTAP1, true
	}
	return "", false
}

// Capabilities probes the registered protocol families and caches the result.
func (client *client) Capabilities(ctx context.Context) (*Capabilities, error) {
	if client.caps != nil {
		return client.caps, nil
	}

	var ctap1Caps *CTAP1Capabilities
	var ctap2Caps *ctap2.GetInfoResponse

	if _, ok := client.invokers[protocol.FamilyCTAP2]; ok {
		request := ctap2.NewGetInfoCommand()
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandGetInfo, nil)
		if err == nil {
			var response ctap2.GetInfoResponse
			if err := request.DecodeResponse(responseBytes, &response); err == nil {
				ctap2Caps = &response
			}
		}
	}

	if _, ok := client.invokers[protocol.FamilyCTAP1]; ok {
		request := ctap1.NewVersionCommand()
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandVersion, nil)
		if err == nil {
			var response ctap1.VersionResponse
			if err := request.DecodeResponse(responseBytes, &response); err == nil {
				ctap1Caps = &CTAP1Capabilities{Version: response.Version}
			}
		}
	}

	caps := buildCapabilities(ctap1Caps, ctap2Caps, client.session.Device())
	if !caps.HasCTAP1() && !caps.HasCTAP2() {
		return nil, ErrNoCapableProtocol
	}

	client.caps = caps
	return client.caps, nil
}

// GetCapabilities returns the detected capabilities using the legacy entry point.
func (client *client) GetCapabilities(ctx context.Context) (*DeviceCapabilities, error) {
	return client.Capabilities(ctx)
}

func buildCapabilities(rawCTAP1 *CTAP1Capabilities, rawCTAP2 *ctap2.GetInfoResponse, device transport.DeviceDescriptor) *Capabilities {
	caps := &Capabilities{
		RawCTAP1: rawCTAP1,
		RawCTAP2: rawCTAP2,
		CTAP1:    rawCTAP1,
		CTAP2:    rawCTAP2,
	}
	caps.Protocols.CTAP1 = rawCTAP1 != nil
	caps.Protocols.CTAP2 = rawCTAP2 != nil
	if preferred, ok := caps.PreferredProtocol(); ok {
		caps.Protocols.Preferred = preferred
	}

	caps.Interaction.UserPresence = caps.HasCTAP1() || caps.HasCTAP2()
	caps.Interaction.NFCImplicitPresence = device.Transport == transport.KindNFC

	if rawCTAP2 == nil {
		return caps
	}

	caps.Authenticator = AuthenticatorCapabilities{
		ResidentKey:                 optionPresent(rawCTAP2, "rk"),
		CredentialManagement:        optionEnabled(rawCTAP2, "credMgmt") || optionEnabled(rawCTAP2, "credentialMgmtPreview"),
		CredentialManagementPreview: optionEnabled(rawCTAP2, "credentialMgmtPreview"),
	}
	caps.Verification = VerificationCapabilities{
		ClientPIN:          optionPresent(rawCTAP2, "clientPin"),
		BuiltInUV:          optionPresent(rawCTAP2, "uv"),
		PinUVAuthToken:     optionEnabled(rawCTAP2, "pinUvAuthToken"),
		BioEnrollment:      optionPresent(rawCTAP2, "bioEnroll"),
		UVRetriesAvailable: optionPresent(rawCTAP2, "uv"),
	}
	caps.Interaction.UserVerification = supportsUserVerification(rawCTAP2)
	caps.Interaction.BuiltInUV = optionPresent(rawCTAP2, "uv")
	return caps
}

func optionPresent(info *ctap2.GetInfoResponse, key string) bool {
	if info == nil || info.Options == nil {
		return false
	}
	_, ok := info.Options[key]
	return ok
}

func optionEnabled(info *ctap2.GetInfoResponse, key string) bool {
	if info == nil || info.Options == nil {
		return false
	}
	return info.Options[key]
}

func supportsUserVerification(info *ctap2.GetInfoResponse) bool {
	return optionPresent(info, "clientPin") || optionPresent(info, "uv")
}
