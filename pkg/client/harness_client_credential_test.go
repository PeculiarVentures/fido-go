//go:build hid_diagnostics

package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

type clientDiagnosticOwnedCredential struct {
	userID                               []byte
	state                                *clientDiagnosticState
	id                                   []byte
	rp                                   string
	verifier                             *diagnosticCredential
	deleted, destroyed, cleanupAttempted bool
}

func clientDiagnosticRandom(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, errors.New("client diagnostic randomness failed")
	}
	return data, nil
}

// CTAP 2.2 section 6.8.7 permits RP display truncation while requiring at
// least 32 stored bytes. This 31-byte fixture keeps full-text readback strict;
// the unpadded base32 encoding preserves every bit of the 128-bit nonce.
func clientDiagnosticRPID(nonce []byte) (string, error) {
	if len(nonce) != 16 {
		return "", errors.New("client diagnostic RP requires a 128-bit nonce")
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(nonce)) + ".test", nil
}

func (state *clientDiagnosticState) createOwned(ctx context.Context) (*clientDiagnosticOwnedCredential, error) {
	if state.unsafe() {
		return nil, errors.New("credential creation stopped after an uncertain operation")
	}
	if !state.current.info.Options["rk"] {
		return nil, diagnostics.SkipReason("discoverable credentials are required for owned cleanup")
	}
	nonce, err := clientDiagnosticRandom(16)
	if err != nil {
		return nil, err
	}
	challenge, err := clientDiagnosticRandom(32)
	if err != nil {
		return nil, err
	}
	rp, err := clientDiagnosticRPID(nonce)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	state.scope.Counter("make_credential_facade_calls", 1)
	registration, err := state.current.sdk.Register(bounded, client.RegistrationRequest{
		RPID: rp, ChallengeHash: challenge, User: client.User{ID: nonce, Name: "SDK diagnostic", DisplayName: "Owned temporary diagnostic"},
		Selection: client.AuthenticatorSelection{UserPresence: client.RequirementRequired, UserVerification: client.UserVerificationRequired},
		CTAP2:     &client.CTAP2RegistrationOptions{ResidentKey: true, CredentialParameters: []client.CredentialParameter{{Type: "public-key", Alg: -7}}},
	})
	var owned *clientDiagnosticOwnedCredential
	if registration != nil && len(registration.CredentialID) > 0 {
		owned = &clientDiagnosticOwnedCredential{state: state, id: append([]byte(nil), registration.CredentialID...), userID: append([]byte(nil), nonce...), rp: rp}
		// Ownership cleanup is registered before any response/public-key validation.
		state.scope.Defer(owned.cleanup)
	}
	if err != nil {
		var status *ctap2.Error
		if owned == nil && !errors.As(err, &status) {
			state.scope.Fact("creation_outcome_uncertain", true)
			state.scope.Defer(func(context.Context) error {
				return errors.New("credential creation outcome is uncertain; no unrelated credential enumeration or deletion is allowed")
			})
		}
		return nil, state.mutationError("owned credential creation failed", err)
	}
	if owned == nil {
		state.mutationUncertain = true
		state.options.Safety.stop()
		state.scope.Fact("creation_outcome_uncertain", true)
		state.scope.Defer(func(context.Context) error {
			return errors.New("created credential identifier is unknown; automatic cleanup is unsafe")
		})
		return nil, errors.New("credential creation did not expose an owned identifier")
	}
	state.scope.Fact("credential_created", true)
	owned.verifier, err = verifyDiagnosticRegistration(registration, rp, true)
	if err != nil {
		return nil, errors.New("owned registration public-key and authenticator-data validation failed")
	}
	state.scope.Fact("registration_verified", true)
	return owned, nil
}
func (owned *clientDiagnosticOwnedCredential) enumerate(ctx context.Context) error {
	state := owned.state
	if state.unsafe() {
		return errors.New("owned credential readback stopped after unsafe authorization")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	listed, err := state.current.ctap.Credentials().List(bounded, client.SecretPINAuthorization(state.pin))
	if err != nil {
		state.scope.Counter("credential_readback_failure_kind", 1)
		return state.failure("owned credential readback failed", err)
	}
	if listed == nil {
		state.scope.Counter("credential_readback_failure_kind", 7)
		return errors.New("owned credential readback was absent")
	}
	matches := 0
	rpMatch, userMatch, hashMatch := true, true, true
	expectedHash := sha256.Sum256([]byte(owned.rp))
	for _, credential := range listed.Credentials {
		if !bytes.Equal(credential.Credential.ID, owned.id) {
			continue
		}
		matches++
		rpMatch = rpMatch && credential.RP.ID == owned.rp
		userMatch = userMatch && bytes.Equal(credential.User.ID, owned.userID)
		hashMatch = hashMatch && bytes.Equal(credential.RPIDHash, expectedHash[:])
	}
	state.scope.Counter("credential_readback_rows", uint64(len(listed.Credentials)))
	state.scope.Counter("credential_readback_id_matches", uint64(matches))
	state.scope.Fact("credential_readback_rp_match", matches > 0 && rpMatch)
	state.scope.Fact("credential_readback_user_match", matches > 0 && userMatch)
	state.scope.Fact("credential_readback_rp_hash_match", matches > 0 && hashMatch)
	kind := uint64(0)
	switch {
	case matches == 0:
		kind = 2
	case matches > 1:
		kind = 3
	case !rpMatch && !userMatch:
		kind = 6
	case !rpMatch:
		kind = 4
	case !userMatch:
		kind = 5
	case !hashMatch:
		kind = 8
	}
	state.scope.Counter("credential_readback_failure_kind", kind)
	if kind != 0 {
		return errors.New("owned credential readback did not have one exact identifier and matching RP/user/hash bindings")
	}
	state.scope.Fact("credential_enumerated", true)
	return nil
}

func (owned *clientDiagnosticOwnedCredential) authenticate(ctx context.Context) error {
	state := owned.state
	if state.unsafe() {
		return errors.New("credential authentication stopped after an uncertain operation")
	}
	challenge, err := clientDiagnosticRandom(32)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	assertion, err := state.current.sdk.Authenticate(bounded, client.AuthenticationRequest{RPID: owned.rp, ChallengeHash: challenge,
		Selection: client.AuthenticatorSelection{UserPresence: client.RequirementRequired, UserVerification: client.UserVerificationRequired},
		// A fresh random RP has exactly this owned resident credential. Omitting
		// allowList requires a credential descriptor even on CTAP 2.0 devices.
		CTAP2: &client.CTAP2AuthenticationOptions{},
	})
	if err != nil {
		return state.failure("owned credential authentication failed", err)
	}
	if err := verifyDiagnosticAssertion(owned.verifier, assertion, challenge); err != nil {
		return errors.New("owned assertion signature or authenticator-data validation failed")
	}
	state.scope.Fact("assertion_signature_verified", true)
	return nil
}
func (owned *clientDiagnosticOwnedCredential) expectAbsent(ctx context.Context) error {
	// The facade emits an awaiting-presence event even for this negative,
	// UP-discouraged probe. It is not an instruction for an operator touch.
	previous := owned.state.suppressTouchMarkers
	owned.state.suppressTouchMarkers = true
	defer func() { owned.state.suppressTouchMarkers = previous }()
	challenge, err := clientDiagnosticRandom(32)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, err = owned.state.current.sdk.Authenticate(bounded, client.AuthenticationRequest{RPID: owned.rp, ChallengeHash: challenge,
		Selection: client.AuthenticatorSelection{UserPresence: client.RequirementDiscouraged, UserVerification: client.UserVerificationDiscouraged},
		CTAP2:     &client.CTAP2AuthenticationOptions{AllowList: []client.CredentialDescriptor{{Type: "public-key", ID: owned.id}}},
	})
	var status *ctap2.Error
	if !errors.As(err, &status) || status.Code != 0x2e {
		return owned.state.failure("owned credential invalidation was not proven by exact NoCredentials status", errOrClientDiagnosticFailure(err))
	}
	owned.state.scope.Fact("owned_credential_invalidation_verified", true)
	return nil
}
func errOrClientDiagnosticFailure(err error) error {
	if err != nil {
		return err
	}
	return errors.New("unexpected successful owned credential assertion")
}

func (owned *clientDiagnosticOwnedCredential) remove(ctx context.Context) error {
	state := owned.state
	if owned.deleted || owned.destroyed {
		return nil
	}
	if owned.cleanupAttempted {
		return errors.New("owned credential deletion was already attempted; no mutation retry is allowed")
	}
	if state.unsafe() {
		return errors.New("owned credential cleanup stopped after uncertain authorization or mutation")
	}
	owned.cleanupAttempted = true
	// A response failure may retire a session without closing the facade, and
	// LIFO cleanup can already have closed a post-replug facade. Acquire a fresh
	// exact enrolled session before the sole Delete call in either case.
	if _, err := state.fresh(ctx); err != nil {
		return err
	}
	state.scope.Counter("delete_credential_facade_calls", 1)
	err := state.current.ctap.Credentials().Delete(ctx, client.CredentialDescriptor{Type: "public-key", ID: owned.id}, client.SecretPINAuthorization(state.pin))
	if err != nil {
		return state.mutationError("owned credential deletion failed", err)
	}
	owned.deleted = true
	state.scope.Fact("owned_credential_deleted", true)
	return owned.expectAbsent(ctx)
}
func (owned *clientDiagnosticOwnedCredential) cleanup(ctx context.Context) error {
	if owned.deleted || owned.destroyed {
		owned.state.scope.Fact("owned_cleanup_complete", true)
		return nil
	}
	err := owned.remove(ctx)
	owned.state.scope.Fact("owned_cleanup_complete", err == nil)
	if err != nil {
		owned.state.options.Safety.stop()
	}
	return err
}
func (state *clientDiagnosticState) credentialScenario(ctx context.Context, persistence bool) error {
	if persistence && !state.options.Persistence || !persistence && !state.options.Credentials {
		return diagnostics.SkipReason("credential mutation scenario was not requested")
	}
	if err := state.managementReady(ctx); err != nil {
		return err
	}
	owned, err := state.createOwned(ctx)
	if err != nil {
		return err
	}
	if err := owned.enumerate(ctx); err != nil {
		return err
	}
	if err := owned.authenticate(ctx); err != nil {
		return err
	}
	if persistence {
		if err := state.powerCycle(ctx, "persistence", false); err != nil {
			return err
		}
		if _, err := state.fresh(ctx); err != nil {
			return err
		}
		if err := owned.authenticate(ctx); err != nil {
			return err
		}
		state.scope.Fact("credential_persisted_verified", true)
	}
	return owned.remove(ctx)
}
