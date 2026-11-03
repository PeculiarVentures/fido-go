//go:build hid_diagnostics

package client_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/fxamacker/cbor/v2"
)

const diagnosticSignatureRP = "signature-fixture.invalid"

func diagnosticSignatureFixture(t *testing.T, uv bool, count uint32) (*client.RegistrationResult, *ecdsa.PrivateKey) {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: big.NewInt(1)}
	fields := map[int64]any{1: int64(2), 3: int64(-7), -1: int64(1), -2: x.FillBytes(make([]byte, 32)), -3: y.FillBytes(make([]byte, 32))}
	encoded := diagnosticSignatureCBOR(t, fields)
	id := []byte("fixture-credential")
	data := diagnosticSignatureHeader(uv, count)
	data[32] |= diagnosticFlagAT
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(id)))
	data = append(data, id...)
	data = append(data, encoded...)
	return &client.RegistrationResult{Protocol: client.FamilyCTAP2, CredentialID: append([]byte(nil), id...),
		AttestationFormat: "none", UserPresent: true, UserVerified: uv,
		RawCTAP2: &ctap2.MakeCredentialResponse{Format: "none", AuthData: data}}, key
}

func diagnosticSignatureCBOR(t *testing.T, value any) []byte {
	t.Helper()
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func diagnosticSignatureHeader(uv bool, count uint32) []byte {
	rp := sha256.Sum256([]byte(diagnosticSignatureRP))
	data := append([]byte(nil), rp[:]...)
	flags := byte(diagnosticFlagUP)
	if uv {
		flags |= diagnosticFlagUV
	}
	data = append(data, flags)
	return binary.BigEndian.AppendUint32(data, count)
}

func diagnosticSignedAssertion(t *testing.T, reg *client.RegistrationResult, key *ecdsa.PrivateKey, hash []byte, uv bool, count uint32) *client.AuthenticationResult {
	t.Helper()
	data := diagnosticSignatureHeader(uv, count)
	digest := sha256.Sum256(append(append([]byte(nil), data...), hash...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return &client.AuthenticationResult{Protocol: client.FamilyCTAP2, CredentialID: append([]byte(nil), reg.CredentialID...),
		Signature: append([]byte(nil), signature...), SignCount: count, UserPresent: true, UserVerified: uv,
		RawCTAP2: &ctap2.GetAssertionResponse{Credential: ctap2.CredentialDescriptor{Type: "public-key", ID: append([]byte(nil), reg.CredentialID...)}, AuthData: data, Signature: signature}}
}

func TestClientDiagnosticSignatureValidatesBindings(t *testing.T) {
	hash := sha256.Sum256([]byte("fresh assertion challenge"))
	cases := map[string]func(*client.AuthenticationResult){
		"corrupt signature": func(a *client.AuthenticationResult) {
			a.RawCTAP2.Signature[len(a.RawCTAP2.Signature)-1] ^= 1
			a.Signature = append([]byte(nil), a.RawCTAP2.Signature...)
		},
		"wrong RP":              func(a *client.AuthenticationResult) { a.RawCTAP2.AuthData[0] ^= 1 },
		"wrong credential":      func(a *client.AuthenticationResult) { a.RawCTAP2.Credential.ID[0] ^= 1 },
		"normalized identifier": func(a *client.AuthenticationResult) { a.CredentialID[0] ^= 1 },
		"normalized signature":  func(a *client.AuthenticationResult) { a.Signature[0] ^= 1 },
		"normalized count":      func(a *client.AuthenticationResult) { a.SignCount++ },
		"normalized flags":      func(a *client.AuthenticationResult) { a.UserVerified = false },
		"missing UP": func(a *client.AuthenticationResult) {
			a.RawCTAP2.AuthData[32] &^= diagnosticFlagUP
			a.UserPresent = false
		},
		"missing UV": func(a *client.AuthenticationResult) {
			a.RawCTAP2.AuthData[32] &^= diagnosticFlagUV
			a.UserVerified = false
		},
		"unexpected AT":        func(a *client.AuthenticationResult) { a.RawCTAP2.AuthData[32] |= diagnosticFlagAT },
		"trailing bytes":       func(a *client.AuthenticationResult) { a.RawCTAP2.AuthData = append(a.RawCTAP2.AuthData, 0) },
		"truncated header":     func(a *client.AuthenticationResult) { a.RawCTAP2.AuthData = a.RawCTAP2.AuthData[:36] },
		"missing raw response": func(a *client.AuthenticationResult) { a.RawCTAP2 = nil },
		"missing signature":    func(a *client.AuthenticationResult) { a.RawCTAP2.Signature = nil; a.Signature = nil },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			reg, key := diagnosticSignatureFixture(t, true, 1)
			credential, err := verifyDiagnosticRegistration(reg, diagnosticSignatureRP, true)
			if err != nil {
				t.Fatal(err)
			}
			assertion := diagnosticSignedAssertion(t, reg, key, hash[:], true, 2)
			corrupt(assertion)
			if verifyDiagnosticAssertion(credential, assertion, hash[:]) == nil {
				t.Fatal("invalid assertion accepted")
			}
			if credential.lastCount != 1 {
				t.Fatal("failed verification advanced the counter")
			}
		})
	}
	reg, key := diagnosticSignatureFixture(t, true, 0)
	credential, err := verifyDiagnosticRegistration(reg, diagnosticSignatureRP, true)
	if err != nil {
		t.Fatal(err)
	}
	assertion := diagnosticSignedAssertion(t, reg, key, hash[:], true, 1)
	wrong := sha256.Sum256([]byte("different challenge"))
	if verifyDiagnosticAssertion(credential, assertion, wrong[:]) == nil || verifyDiagnosticAssertion(credential, assertion, hash[:31]) == nil {
		t.Fatal("assertion accepted the wrong client-data hash")
	}
	if err = verifyDiagnosticAssertion(credential, assertion, hash[:]); err != nil {
		t.Fatal(err)
	}
	if verifyDiagnosticAssertion(credential, assertion, hash[:]) == nil {
		t.Fatal("non-increasing nonzero counter accepted")
	}
}

func TestClientDiagnosticSignatureRejectsMalformedRegistration(t *testing.T) {
	cases := map[string]func(*client.RegistrationResult){
		"missing raw":         func(r *client.RegistrationResult) { r.RawCTAP2 = nil },
		"wrong normalized ID": func(r *client.RegistrationResult) { r.CredentialID[0] ^= 1 },
		"wrong RP":            func(r *client.RegistrationResult) { r.RawCTAP2.AuthData[0] ^= 1 },
		"missing AT":          func(r *client.RegistrationResult) { r.RawCTAP2.AuthData[32] &^= diagnosticFlagAT },
		"missing UV": func(r *client.RegistrationResult) {
			r.RawCTAP2.AuthData[32] &^= diagnosticFlagUV
			r.UserVerified = false
		},
		"short header":            func(r *client.RegistrationResult) { r.RawCTAP2.AuthData = r.RawCTAP2.AuthData[:54] },
		"oversized credential ID": func(r *client.RegistrationResult) { r.RawCTAP2.AuthData[53], r.RawCTAP2.AuthData[54] = 255, 255 },
		"truncated key": func(r *client.RegistrationResult) {
			r.RawCTAP2.AuthData = r.RawCTAP2.AuthData[:len(r.RawCTAP2.AuthData)-1]
		},
		"trailing key bytes": func(r *client.RegistrationResult) { r.RawCTAP2.AuthData = append(r.RawCTAP2.AuthData, 0) },
		"invalid extension": func(r *client.RegistrationResult) {
			r.RawCTAP2.AuthData[32] |= diagnosticFlagED
			r.RawCTAP2.AuthData = append(r.RawCTAP2.AuthData, 0xf6)
		},
		"oversized auth data": func(r *client.RegistrationResult) { r.RawCTAP2.AuthData = make([]byte, diagnosticAuthDataLimit+1) },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			reg, _ := diagnosticSignatureFixture(t, true, 0)
			corrupt(reg)
			if _, err := verifyDiagnosticRegistration(reg, diagnosticSignatureRP, true); err == nil {
				t.Fatal("malformed registration accepted")
			}
		})
	}
	for name, fields := range map[string]map[int64]any{
		"algorithm":        {1: 2, 3: -257, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)},
		"curve":            {1: 2, 3: -7, -1: 2, -2: make([]byte, 32), -3: make([]byte, 32)},
		"key type":         {1: 1, 3: -7, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)},
		"short coordinate": {1: 2, 3: -7, -1: 1, -2: make([]byte, 31), -3: make([]byte, 32)},
		"off curve":        {1: 2, 3: -7, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)},
	} {
		t.Run(name, func(t *testing.T) {
			reg, _ := diagnosticSignatureFixture(t, false, 0)
			keyOffset := 55 + len(reg.CredentialID)
			reg.RawCTAP2.AuthData = append(reg.RawCTAP2.AuthData[:keyOffset], diagnosticSignatureCBOR(t, fields)...)
			if _, err := verifyDiagnosticRegistration(reg, diagnosticSignatureRP, false); err == nil {
				t.Fatal("unsupported or malformed public key accepted")
			}
		})
	}
}

func TestClientDiagnosticSignaturePermitsZeroCounters(t *testing.T) {
	reg, key := diagnosticSignatureFixture(t, false, 0)
	credential, err := verifyDiagnosticRegistration(reg, diagnosticSignatureRP, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, challenge := range []string{"first fresh challenge", "second fresh challenge"} {
		hash := sha256.Sum256([]byte(challenge))
		assertion := diagnosticSignedAssertion(t, reg, key, hash[:], false, 0)
		if err = verifyDiagnosticAssertion(credential, assertion, hash[:]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientDiagnosticSignatureRejectsAmbiguousCOSE(t *testing.T) {
	reg, _ := diagnosticSignatureFixture(t, false, 0)
	keyOffset := 55 + len(reg.CredentialID)
	canonical := append([]byte(nil), reg.RawCTAP2.AuthData[keyOffset:]...)
	fixtures := map[string][]byte{
		"duplicate label":    append([]byte{0xa6, 0x01, 0x02}, canonical[1:]...),
		"nonminimal integer": append([]byte{0xa5, 0x01, 0x18, 0x02}, canonical[3:]...),
		"tagged key":         append([]byte{0xd9, 0xd9, 0xf7}, canonical...),
	}
	for name, encoded := range fixtures {
		t.Run(name, func(t *testing.T) {
			copyReg, _ := diagnosticSignatureFixture(t, false, 0)
			copyReg.RawCTAP2.AuthData = append(copyReg.RawCTAP2.AuthData[:keyOffset], encoded...)
			if _, err := verifyDiagnosticRegistration(copyReg, diagnosticSignatureRP, false); err == nil {
				t.Fatal("ambiguous or noncanonical COSE key accepted")
			}
		})
	}
}
