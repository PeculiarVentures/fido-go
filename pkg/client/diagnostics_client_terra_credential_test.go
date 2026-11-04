//go:build hid_diagnostics

package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

type terraReadbackCredentials struct {
	client.CredentialManager
	items []client.DiscoverableCredential
}

func TestTerraDiagnosticRPIDIsShortAndPreservesNonce(t *testing.T) {
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	rp, err := clientDiagnosticRPID(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(rp) > 32 || !strings.HasSuffix(rp, ".test") || rp != strings.ToLower(rp) {
		t.Fatalf("invalid RP format")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSuffix(rp, ".test")))
	if err != nil || !bytes.Equal(decoded, nonce) {
		t.Fatal("RP encoding did not preserve the 128-bit nonce")
	}
	for _, size := range []int{0, 15, 17} {
		if _, err := clientDiagnosticRPID(make([]byte, size)); err == nil {
			t.Fatalf("accepted nonce length %d", size)
		}
	}
}

func (c terraReadbackCredentials) List(context.Context, client.UVAuthorization) (*client.CredentialListResult, error) {
	return &client.CredentialListResult{Credentials: c.items}, nil
}

type terraReadbackCTAP struct {
	client.CTAP2Client
	items []client.DiscoverableCredential
}

func (c terraReadbackCTAP) Credentials() client.CredentialManager {
	return terraReadbackCredentials{items: c.items}
}

func TestTerraOwnedCredentialReadbackRequiresExactUniqueMetadata(t *testing.T) {
	entry := client.DiscoverableCredential{Credential: client.CredentialDescriptor{Type: "public-key", ID: []byte("owned")}, RP: ctap2.RelyingPartyEntity{ID: "example.invalid"}, User: ctap2.UserEntity{ID: []byte("user")}}
	hash := sha256.Sum256([]byte("example.invalid"))
	entry.RPIDHash = hash[:]
	wrongRP := entry
	wrongRP.RP.ID = "other.invalid"
	wrongUser := entry
	wrongUser.User.ID = []byte("other")
	other := entry
	other.Credential.ID = []byte("unrelated")
	wrongHash := entry
	wrongHash.RPIDHash = make([]byte, 32)
	for _, tc := range []struct {
		name  string
		items []client.DiscoverableCredential
		pass  bool
		kind  uint64
	}{
		{"one matching", []client.DiscoverableCredential{other, entry}, true, 0}, {"absent", []client.DiscoverableCredential{other}, false, 2}, {"wrong rp", []client.DiscoverableCredential{wrongRP}, false, 4}, {"wrong user", []client.DiscoverableCredential{wrongUser}, false, 5}, {"duplicate", []client.DiscoverableCredential{entry, entry}, false, 3}, {"wrong hash", []client.DiscoverableCredential{wrongHash}, false, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "readback", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
				state := &clientDiagnosticState{scope: scope, current: &clientDiagnosticSession{ctap: terraReadbackCTAP{items: tc.items}}}
				owned := &clientDiagnosticOwnedCredential{state: state, id: []byte("owned"), rp: "example.invalid", userID: []byte("user")}
				return owned.enumerate(ctx)
			}}}, diagnostics.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if (report.Results[0].Status == diagnostics.Pass) != tc.pass {
				t.Fatalf("unexpected result: %s", report.Results[0].Status)
			}
			if report.Results[0].Facts["credential_enumerated"] != tc.pass {
				t.Fatal("incorrect readback fact")
			}
			if report.Results[0].Counters["credential_readback_failure_kind"] != tc.kind {
				t.Fatalf("incorrect failure classification")
			}
		})
	}
}

type terraTouchClient struct {
	client.Client
	state *clientDiagnosticState
}

func (c terraTouchClient) Authenticate(ctx context.Context, _ client.AuthenticationRequest) (*client.AuthenticationResult, error) {
	c.state.OnInteraction(ctx, client.InteractionEvent{Kind: client.InteractionAwaitingUserPresence, Operation: "authenticate"})
	return nil, &ctap2.Error{Code: 0x2e}
}
func TestTerraNegativeProbeDoesNotPromptForTouch(t *testing.T) {
	var output bytes.Buffer
	var state *clientDiagnosticState
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "probe", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		state = &clientDiagnosticState{scope: scope, options: clientDiagnosticOptions{Output: &output}}
		state.current = &clientDiagnosticSession{sdk: terraTouchClient{state: state}}
		return (&clientDiagnosticOwnedCredential{state: state, id: []byte("id"), rp: "example.invalid"}).expectAbsent(ctx)
	}}}, diagnostics.Options{})
	if err != nil || report.Results[0].Status != diagnostics.Pass {
		t.Fatal("negative probe failed")
	}
	if output.Len() != 0 {
		t.Fatal("negative probe emitted a touch prompt")
	}
	state.OnInteraction(context.Background(), client.InteractionEvent{Kind: client.InteractionAwaitingUserPresence, Operation: "authenticate"})
	if output.String() != "CLIENT_INTERACTION operation=authenticate kind=touch\n" {
		t.Fatal("ordinary touch marker suppressed")
	}
}
