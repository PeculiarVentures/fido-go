//go:build hid_diagnostics

package client_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/fxamacker/cbor/v2"
)

const (
	diagnosticAuthDataLimit = 64 * 1024
	diagnosticFlagUP        = 0x01
	diagnosticFlagUV        = 0x04
	diagnosticFlagAT        = 0x40
	diagnosticFlagED        = 0x80
)

// This harness implements the authenticator-data bindings from CTAP 2.2
// sections 6.1/6.2 and WebAuthn Level 2 sections 6.1, 6.5.1, and 7.2.
// It extracts the registered key; it does not establish attestation trust.
type diagnosticCredential struct {
	publicKey    *ecdsa.PublicKey
	credentialID []byte
	rpHash       [32]byte
	requireUV    bool
	lastCount    uint32
}

func verifyDiagnosticRegistration(reg *client.RegistrationResult, rpID string, requireUV bool) (*diagnosticCredential, error) {
	if reg == nil || reg.Protocol != client.FamilyCTAP2 || reg.RawCTAP2 == nil || reg.RawCTAP1 != nil || rpID == "" || len(rpID) > 253 {
		return nil, errors.New("diagnostic registration requires a CTAP2 response and expected RP ID")
	}
	data := reg.RawCTAP2.AuthData
	rpHash := sha256.Sum256([]byte(rpID))
	flags, count, err := diagnosticAuthDataHeader(data, rpHash, requireUV)
	if err != nil {
		return nil, err
	}
	if flags&diagnosticFlagAT == 0 || len(data) < 55 || reg.RawCTAP2.Format == "" || reg.AttestationFormat != reg.RawCTAP2.Format {
		return nil, errors.New("diagnostic registration lacks complete attested credential data")
	}
	if reg.UserPresent != (flags&diagnosticFlagUP != 0) || reg.UserVerified != (flags&diagnosticFlagUV != 0) {
		return nil, errors.New("diagnostic registration normalized flags disagree with signed data")
	}
	idLength := int(binary.BigEndian.Uint16(data[53:55]))
	if idLength == 0 || idLength > len(data)-55 || !bytes.Equal(reg.CredentialID, data[55:55+idLength]) {
		return nil, errors.New("diagnostic registration credential identifier is missing or inconsistent")
	}
	key, remaining, err := diagnosticES256Key(data[55+idLength:])
	if err != nil {
		return nil, err
	}
	if err = diagnosticAuthDataTail(remaining, flags); err != nil {
		return nil, err
	}
	return &diagnosticCredential{publicKey: key, credentialID: append([]byte(nil), reg.CredentialID...), rpHash: rpHash, requireUV: requireUV, lastCount: count}, nil
}

// Keep this state across assertions. The counter is updated only after every
// binding and signature check succeeds. Unsupported all-zero counters are valid;
// if either counter is nonzero, the new count must increase (WebAuthn 6.1.1).
func verifyDiagnosticAssertion(credential *diagnosticCredential, assertion *client.AuthenticationResult, challengeHash []byte) error {
	if credential == nil || credential.publicKey == nil || credential.publicKey.Curve != elliptic.P256() ||
		credential.publicKey.X == nil || credential.publicKey.Y == nil || len(credential.credentialID) == 0 ||
		!elliptic.P256().IsOnCurve(credential.publicKey.X, credential.publicKey.Y) {
		return errors.New("diagnostic assertion has no validated ES256 credential")
	}
	if assertion == nil || assertion.Protocol != client.FamilyCTAP2 || assertion.RawCTAP2 == nil || assertion.RawCTAP1 != nil || len(challengeHash) != sha256.Size {
		return errors.New("diagnostic assertion requires a CTAP2 response and 32-byte client-data hash")
	}
	raw := assertion.RawCTAP2
	if raw.Credential.Type != "public-key" || !bytes.Equal(raw.Credential.ID, credential.credentialID) ||
		!bytes.Equal(assertion.CredentialID, credential.credentialID) || !bytes.Equal(assertion.Signature, raw.Signature) ||
		len(raw.Signature) < 8 || len(raw.Signature) > 72 {
		return errors.New("diagnostic assertion credential or signature is missing or inconsistent")
	}
	flags, count, err := diagnosticAuthDataHeader(raw.AuthData, credential.rpHash, credential.requireUV)
	if err != nil {
		return err
	}
	if flags&diagnosticFlagAT != 0 {
		return errors.New("diagnostic assertion unexpectedly includes attested credential data")
	}
	if err = diagnosticAuthDataTail(raw.AuthData[37:], flags); err != nil {
		return err
	}
	if assertion.UserPresent != (flags&diagnosticFlagUP != 0) || assertion.UserVerified != (flags&diagnosticFlagUV != 0) || assertion.SignCount != count {
		return errors.New("diagnostic assertion normalized flags or counter disagree with signed data")
	}
	digest := sha256.New()
	_, _ = digest.Write(raw.AuthData)
	_, _ = digest.Write(challengeHash)
	if !ecdsa.VerifyASN1(credential.publicKey, digest.Sum(nil), raw.Signature) {
		return errors.New("diagnostic ES256 assertion signature is invalid")
	}
	if (count != 0 || credential.lastCount != 0) && count <= credential.lastCount {
		return errors.New("diagnostic assertion signature counter did not increase")
	}
	credential.lastCount = count
	return nil
}

// The one-shot bridge uses UP-required/UV-optional policy. Multi-assertion flows
// use the two-step API above so the same credential tracks counter progression.
func verifyClientDiagnosticAssertion(reg *client.RegistrationResult, assertion *client.AuthenticationResult, rpID string, challengeHash []byte) error {
	credential, err := verifyDiagnosticRegistration(reg, rpID, false)
	if err != nil {
		return err
	}
	return verifyDiagnosticAssertion(credential, assertion, challengeHash)
}

func diagnosticAuthDataHeader(data []byte, rpHash [32]byte, requireUV bool) (byte, uint32, error) {
	if len(data) < 37 || len(data) > diagnosticAuthDataLimit || !bytes.Equal(data[:32], rpHash[:]) {
		return 0, 0, errors.New("diagnostic authenticator data is malformed or bound to the wrong RP")
	}
	flags := data[32]
	if flags&diagnosticFlagUP == 0 || (requireUV && flags&diagnosticFlagUV == 0) {
		return 0, 0, errors.New("diagnostic authenticator data lacks required UP or UV")
	}
	return flags, binary.BigEndian.Uint32(data[33:37]), nil
}

func diagnosticCBORMode() (cbor.DecMode, error) {
	return (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
	}).DecMode()
}

func diagnosticAuthDataTail(data []byte, flags byte) error {
	if flags&diagnosticFlagED == 0 {
		if len(data) != 0 {
			return errors.New("diagnostic authenticator data has unexpected trailing bytes")
		}
		return nil
	}
	if len(data) == 0 || data[0]>>5 != 5 {
		return errors.New("diagnostic authenticator extension data is not a CBOR map")
	}
	mode, err := diagnosticCBORMode()
	if err != nil {
		return errors.New("diagnostic CBOR configuration is invalid")
	}
	var extensions map[string]cbor.RawMessage
	if err = mode.Unmarshal(data, &extensions); err != nil {
		return errors.New("diagnostic authenticator extension data is malformed")
	}
	return nil
}

func diagnosticES256Key(data []byte) (*ecdsa.PublicKey, []byte, error) {
	if len(data) == 0 || data[0]>>5 != 5 {
		return nil, nil, errors.New("diagnostic credential key is missing its COSE map")
	}
	mode, err := diagnosticCBORMode()
	if err != nil {
		return nil, nil, errors.New("diagnostic CBOR configuration is invalid")
	}
	var fields map[int64]cbor.RawMessage
	remaining, err := mode.UnmarshalFirst(data, &fields)
	if err != nil || len(fields) != 5 {
		return nil, nil, errors.New("diagnostic credential COSE key is malformed or contains unexpected parameters")
	}
	for label, expected := range map[int64]int64{1: 2, 3: -7, -1: 1} {
		var value int64
		encoded, present := fields[label]
		if !present || mode.Unmarshal(encoded, &value) != nil || value != expected {
			return nil, nil, errors.New("diagnostic credential key is not EC2/P-256/ES256")
		}
	}
	var x, y []byte
	if mode.Unmarshal(fields[-2], &x) != nil || mode.Unmarshal(fields[-3], &y) != nil || len(x) != 32 || len(y) != 32 {
		return nil, nil, errors.New("diagnostic credential key coordinates must each be 32 bytes")
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, nil, errors.New("diagnostic credential key is not on P-256")
	}
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, nil, errors.New("diagnostic CBOR configuration is invalid")
	}
	canonical, err := encoder.Marshal(map[int64]any{1: int64(2), 3: int64(-7), -1: int64(1), -2: x, -3: y})
	if err != nil || !bytes.Equal(canonical, data[:len(data)-len(remaining)]) {
		return nil, nil, errors.New("diagnostic credential key is not CTAP2 canonical CBOR")
	}
	return key, remaining, nil
}
