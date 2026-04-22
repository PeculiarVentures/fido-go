package ctap2

// AuthenticatorTransport identifies a transport reported by CTAP2.
type AuthenticatorTransport string

const (
	// TransportUSB reports USB transport support.
	TransportUSB AuthenticatorTransport = "usb"
	// TransportNFC reports NFC transport support.
	TransportNFC AuthenticatorTransport = "nfc"
	// TransportBLE reports BLE transport support.
	TransportBLE AuthenticatorTransport = "ble"
	// TransportInternal reports a platform-bound authenticator.
	TransportInternal AuthenticatorTransport = "internal"
)

// Extensions is the extension input or output map used by CTAP2 commands.
type Extensions map[string]any

// RelyingPartyEntity describes the relying party for MakeCredential requests.
type RelyingPartyEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

// UserEntity describes the user account bound to a credential.
type UserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

// CredentialParameter describes one requested public-key credential algorithm.
type CredentialParameter struct {
	Type string `cbor:"type"`
	Alg  int64  `cbor:"alg"`
}

// CredentialDescriptor identifies an existing credential.
type CredentialDescriptor struct {
	Type       string                   `cbor:"type"`
	ID         []byte                   `cbor:"id"`
	Transports []AuthenticatorTransport `cbor:"transports,omitempty"`
}

// MakeCredentialOptions contains the standard MakeCredential option keys.
type MakeCredentialOptions struct {
	ResidentKey      bool `cbor:"rk,omitempty"`
	UserPresence     bool `cbor:"up,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
}

// GetAssertionOptions contains the standard GetAssertion option keys.
type GetAssertionOptions struct {
	UserPresence     bool `cbor:"up,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
}

// Permission identifies one ClientPIN permission bit.
type Permission uint8

const (
	// PermissionMakeCredential grants MakeCredential authorization.
	PermissionMakeCredential Permission = 0x01
	// PermissionGetAssertion grants GetAssertion authorization.
	PermissionGetAssertion Permission = 0x02
	// PermissionCredentialManagement grants credential-management authorization.
	PermissionCredentialManagement Permission = 0x04
	// PermissionBioEnrollment grants bio-enrollment authorization.
	PermissionBioEnrollment Permission = 0x08
	// PermissionLargeBlobWrite grants large-blob write authorization.
	PermissionLargeBlobWrite Permission = 0x10
	// PermissionAuthenticatorConfig grants authenticator configuration authorization.
	PermissionAuthenticatorConfig Permission = 0x20
)
