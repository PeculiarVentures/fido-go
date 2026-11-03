//go:build hid_diagnostics

package client_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

func TestTerraDiagnosticAssertionRejectsMutationAndReplay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("example.test"))
	challenge := sha256.Sum256([]byte("challenge"))
	id := []byte("credential")
	credential := &diagnosticCredential{publicKey: &key.PublicKey, credentialID: id, rpHash: rpHash, lastCount: 4}
	authData := make([]byte, 37)
	copy(authData, rpHash[:])
	authData[32] = diagnosticFlagUP
	binary.BigEndian.PutUint32(authData[33:], 5)
	h := sha256.New()
	h.Write(authData)
	h.Write(challenge[:])
	signature, err := ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	raw := &ctap2.GetAssertionResponse{Credential: ctap2.CredentialDescriptor{Type: "public-key", ID: id}, AuthData: authData, Signature: signature}
	assertion := &client.AuthenticationResult{Protocol: client.FamilyCTAP2, CredentialID: id, Signature: signature, SignCount: 5, UserPresent: true, RawCTAP2: raw}
	badChallenge := challenge
	badChallenge[0] ^= 1
	if err := verifyDiagnosticAssertion(credential, assertion, badChallenge[:]); err == nil {
		t.Fatal("mutated challenge accepted")
	}
	if credential.lastCount != 4 {
		t.Fatal("failed verification advanced counter")
	}
	if err := verifyDiagnosticAssertion(credential, assertion, challenge[:]); err != nil {
		t.Fatalf("valid assertion: %v", err)
	}
	if err := verifyDiagnosticAssertion(credential, assertion, challenge[:]); err == nil {
		t.Fatal("replayed counter accepted")
	}
}
