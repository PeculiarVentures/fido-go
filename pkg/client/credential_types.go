package client

import "github.com/PeculiarVentures/fido-go/pkg/ctap2"

// AuthenticatorTransport identifies one credential transport in the public facade API.
type AuthenticatorTransport string

const (
	// AuthenticatorTransportUSB reports USB transport support.
	AuthenticatorTransportUSB AuthenticatorTransport = "usb"
	// AuthenticatorTransportNFC reports NFC transport support.
	AuthenticatorTransportNFC AuthenticatorTransport = "nfc"
	// AuthenticatorTransportBLE reports BLE transport support.
	AuthenticatorTransportBLE AuthenticatorTransport = "ble"
	// AuthenticatorTransportInternal reports a platform-bound authenticator.
	AuthenticatorTransportInternal AuthenticatorTransport = "internal"
)

// CredentialParameter describes one requested public-key credential algorithm in the public facade API.
type CredentialParameter struct {
	Type string
	Alg  int64
}

// CredentialDescriptor identifies an existing credential in the public facade API.
type CredentialDescriptor struct {
	Type       string
	ID         []byte
	Transports []AuthenticatorTransport
}

func credentialParameterToCTAP2(parameter CredentialParameter) ctap2.CredentialParameter {
	return ctap2.CredentialParameter{Type: parameter.Type, Alg: parameter.Alg}
}

func credentialParametersToCTAP2(parameters []CredentialParameter) []ctap2.CredentialParameter {
	if len(parameters) == 0 {
		return nil
	}
	result := make([]ctap2.CredentialParameter, len(parameters))
	for index, parameter := range parameters {
		result[index] = credentialParameterToCTAP2(parameter)
	}
	return result
}

func credentialDescriptorToCTAP2(descriptor CredentialDescriptor) ctap2.CredentialDescriptor {
	result := ctap2.CredentialDescriptor{
		Type: descriptor.Type,
		ID:   append([]byte(nil), descriptor.ID...),
	}
	if len(descriptor.Transports) != 0 {
		result.Transports = make([]ctap2.AuthenticatorTransport, len(descriptor.Transports))
		for index, transport := range descriptor.Transports {
			result.Transports[index] = ctap2.AuthenticatorTransport(transport)
		}
	}
	return result
}

func credentialDescriptorsToCTAP2(descriptors []CredentialDescriptor) []ctap2.CredentialDescriptor {
	if len(descriptors) == 0 {
		return nil
	}
	result := make([]ctap2.CredentialDescriptor, len(descriptors))
	for index, descriptor := range descriptors {
		result[index] = credentialDescriptorToCTAP2(descriptor)
	}
	return result
}

func credentialDescriptorFromCTAP2(descriptor ctap2.CredentialDescriptor) CredentialDescriptor {
	result := CredentialDescriptor{
		Type: descriptor.Type,
		ID:   append([]byte(nil), descriptor.ID...),
	}
	if len(descriptor.Transports) != 0 {
		result.Transports = make([]AuthenticatorTransport, len(descriptor.Transports))
		for index, transport := range descriptor.Transports {
			result.Transports[index] = AuthenticatorTransport(transport)
		}
	}
	return result
}
