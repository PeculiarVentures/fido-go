//go:build hid_diagnostics && (darwin || linux)

package client_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

type terraRestoreLocator struct {
	opens, closes, authorizations, changes int
	failRestore, validAuthorization        bool
	deleted                                []byte
}

func (l *terraRestoreLocator) List(context.Context) ([]client.Device, error) {
	return []client.Device{{ID: "target"}}, nil
}
func (l *terraRestoreLocator) Open(context.Context, string, ...client.Option) (client.Client, error) {
	l.opens++
	return &terraRestoreClient{owner: l}, nil
}

type terraRestoreClient struct {
	client.Client
	owner  *terraRestoreLocator
	closed bool
}

func (c *terraRestoreClient) CTAP2(context.Context) (client.CTAP2Client, error) {
	return terraRestoreCTAP{owner: c.owner}, nil
}
func (c *terraRestoreClient) Register(context.Context, client.RegistrationRequest) (*client.RegistrationResult, error) {
	return &client.RegistrationResult{CredentialID: []byte("owned")}, nil
}
func (c *terraRestoreClient) Authenticate(context.Context, client.AuthenticationRequest) (*client.AuthenticationResult, error) {
	return nil, &ctap2.Error{Code: 0x2e}
}
func (c *terraRestoreClient) CloseContext(context.Context) error {
	if !c.closed {
		c.closed = true
		c.owner.closes++
	}
	return nil
}

type terraRestoreCTAP struct {
	client.CTAP2Client
	owner *terraRestoreLocator
}

func (c terraRestoreCTAP) Info(context.Context) (*client.AuthenticatorInfo, error) {
	return &client.AuthenticatorInfo{Options: map[string]bool{"clientPin": true, "credMgmt": true, "rk": true}}, nil
}
func (c terraRestoreCTAP) PIN() client.PINManager { return terraRestorePIN{owner: c.owner} }
func (c terraRestoreCTAP) Credentials() client.CredentialManager {
	return terraRestoreCredentials{owner: c.owner}
}

type terraRestorePIN struct {
	client.PINManager
	owner *terraRestoreLocator
}

func (p terraRestorePIN) Change(context.Context, client.Secret, client.Secret) error {
	p.owner.changes++
	if p.owner.failRestore && p.owner.changes == 2 {
		return &ctap2.Error{Code: 0x37}
	}
	return nil
}

type terraRestoreCredentials struct {
	client.CredentialManager
	owner *terraRestoreLocator
}

func (c terraRestoreCredentials) List(context.Context, client.UVAuthorization) (*client.CredentialListResult, error) {
	c.owner.authorizations++
	if c.owner.authorizations == 2 && !c.owner.validAuthorization {
		return nil, context.DeadlineExceeded
	}
	return &client.CredentialListResult{}, nil
}
func (c terraRestoreCredentials) Delete(_ context.Context, d client.CredentialDescriptor, _ client.UVAuthorization) error {
	c.owner.deleted = append([]byte(nil), d.ID...)
	return nil
}

func TestTerraRestoreCleanupClosesSessionsAcquiredDuringCleanup(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	temporary := filepath.Join(dir, "temporary")
	if err := os.WriteFile(original, []byte("123456"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, []byte("654321"), 0600); err != nil {
		t.Fatal(err)
	}
	loc := &terraRestoreLocator{}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "restore", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		state, e := newClientDiagnosticState(scope, clientDiagnosticOptions{Endpoint: "target", Locator: loc, PINChange: true, PINFile: original, TempPINFile: temporary})
		if e != nil {
			return e
		}
		return state.changePIN(ctx)
	}}}, diagnostics.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Status == diagnostics.Pass {
		t.Fatal("original authorization failure was lost")
	}
	if loc.changes != 2 {
		t.Errorf("changes=%d, expected temporary change and exactly one restoration", loc.changes)
	}
	if loc.opens != loc.closes {
		t.Errorf("cleanup leaked SDK sessions: opens=%d closes=%d", loc.opens, loc.closes)
	}
	if !report.Results[0].Facts["original_pin_restored_verified"] {
		t.Error("original PIN restoration was not verified")
	}
}

func TestTerraCatalogFailureStopsNextButRunsSafeCleanup(t *testing.T) {
	for _, kind := range []string{"restore-policy-rejection", "invalid-registration"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			original := filepath.Join(dir, "original")
			temporary := filepath.Join(dir, "temporary")
			if err := os.WriteFile(original, []byte("123456"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(temporary, []byte("654321"), 0600); err != nil {
				t.Fatal(err)
			}
			loc := &terraRestoreLocator{validAuthorization: true, failRestore: kind == "restore-policy-rejection"}
			options := clientDiagnosticOptions{Endpoint: "target", Locator: loc, Hardware: true, Credentials: true, PINChange: true, PINFile: original, TempPINFile: temporary}
			all, err := clientDiagnosticScenarios(options)
			if err != nil {
				t.Fatal(err)
			}
			first := "client.pin-change"
			if kind == "invalid-registration" {
				first = "client.credential-lifecycle"
			}
			selected, err := diagnostics.Select(all, []string{first, "client.info-pin-status"})
			if err != nil {
				t.Fatal(err)
			}
			report, err := diagnostics.Run(context.Background(), selected, diagnostics.Options{Capabilities: clientDiagnosticCapabilities(options), EnabledModes: map[diagnostics.Mode]bool{diagnostics.Hardware: true}})
			if err != nil {
				t.Fatal(err)
			}
			if report.Results[0].Status == diagnostics.Pass || report.Results[1].Status != diagnostics.Skip {
				t.Fatalf("unexpected statuses: %s, %s", report.Results[0].Status, report.Results[1].Status)
			}
			if kind == "restore-policy-rejection" && loc.changes != 2 {
				t.Errorf("restore retried or not attempted: %d", loc.changes)
			}
			if kind == "invalid-registration" && string(loc.deleted) != "owned" {
				t.Errorf("cleanup did not delete exactly owned credential")
			}
			if loc.opens != loc.closes {
				t.Errorf("unclosed sessions: %d opens %d closes", loc.opens, loc.closes)
			}
		})
	}
}
