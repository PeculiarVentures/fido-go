package ctap2

import "fmt"

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

const (
	// COSEKeyTypeEC2 identifies an elliptic-curve COSE key.
	COSEKeyTypeEC2 int64 = 2
	// COSEAlgorithmECDHESHKDF256 identifies the P-256 ECDH key-agreement algorithm used by ClientPIN.
	COSEAlgorithmECDHESHKDF256 int64 = -25
	// COSECurveP256 identifies the NIST P-256 curve.
	COSECurveP256 int64 = 1
)

// COSEKey describes a COSE EC2 public key used by CTAP2 ClientPIN key agreement.
type COSEKey struct {
	KeyType   int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint,omitempty"`
	Curve     int64  `cbor:"-1,keyasint,omitempty"`
	X         []byte `cbor:"-2,keyasint,omitempty"`
	Y         []byte `cbor:"-3,keyasint,omitempty"`
}

// Clone returns a defensive copy of the COSE key.
func (key *COSEKey) Clone() *COSEKey {
	if key == nil {
		return nil
	}
	clone := *key
	clone.X = append([]byte(nil), key.X...)
	clone.Y = append([]byte(nil), key.Y...)
	return &clone
}

// ValidateEC2 reports whether the key is a supported P-256 EC2 public key.
func (key *COSEKey) ValidateEC2() error {
	if key == nil {
		return fmt.Errorf("ctap2: COSE key is required")
	}
	if key.KeyType != COSEKeyTypeEC2 {
		return fmt.Errorf("ctap2: COSE key type must be %d", COSEKeyTypeEC2)
	}
	if key.Algorithm != 0 && key.Algorithm != COSEAlgorithmECDHESHKDF256 {
		return fmt.Errorf("ctap2: COSE key algorithm must be %d", COSEAlgorithmECDHESHKDF256)
	}
	if key.Curve != COSECurveP256 {
		return fmt.Errorf("ctap2: COSE key curve must be %d", COSECurveP256)
	}
	if len(key.X) == 0 || len(key.Y) == 0 {
		return fmt.Errorf("ctap2: COSE key must include both EC2 coordinates")
	}
	if len(key.X) > 32 || len(key.Y) > 32 {
		return fmt.Errorf("ctap2: COSE key coordinates must be at most 32 bytes")
	}
	return nil
}

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
