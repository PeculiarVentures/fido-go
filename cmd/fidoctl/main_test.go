package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type fakeService struct {
	devices     []client.Device
	listErr     error
	info        *fidoctl.InfoResult
	raw         *fidoctl.RawResult
	credentials *fidoctl.CredentialListResult
	retries     *fidoctl.PINRetriesResult
	setCalls    int
	changeCalls int
	resetCalls  int
	setPIN      client.Secret
	currentPIN  client.Secret
	newPIN      client.Secret
}

func (service *fakeService) ListDevices(context.Context) ([]client.Device, error) {
	return service.devices, service.listErr
}

func (service *fakeService) Info(context.Context, string) (*fidoctl.InfoResult, error) {
	return service.info, nil
}

func (service *fakeService) Raw(context.Context, fidoctl.RawRequest) (*fidoctl.RawResult, error) {
	return service.raw, nil
}

func (service *fakeService) Trace(context.Context, fidoctl.RawRequest) (*fidoctl.TraceResult, error) {
	return &fidoctl.TraceResult{Response: service.raw.Response}, nil
}

func (service *fakeService) PINRetries(context.Context, string) (*fidoctl.PINRetriesResult, error) {
	return service.retries, nil
}

func (service *fakeService) SetPIN(_ context.Context, _ string, newPIN client.Secret) error {
	service.setCalls++
	service.setPIN = newPIN.Clone()
	return nil
}

func (service *fakeService) ChangePIN(_ context.Context, _ string, currentPIN client.Secret, newPIN client.Secret) error {
	service.changeCalls++
	service.currentPIN = currentPIN.Clone()
	service.newPIN = newPIN.Clone()
	return nil
}

func (service *fakeService) Register(context.Context, string, client.RegistrationRequest) (*client.RegistrationResult, error) {
	return &client.RegistrationResult{Protocol: client.FamilyCTAP2}, nil
}

func (service *fakeService) Authenticate(context.Context, string, client.AuthenticationRequest) (*client.AuthenticationResult, error) {
	return &client.AuthenticationResult{Protocol: client.FamilyCTAP2}, nil
}

func (service *fakeService) Reset(context.Context, string) error {
	service.resetCalls++
	return nil
}

func (service *fakeService) ListCredentials(context.Context, string, client.Secret) (*fidoctl.CredentialListResult, error) {
	return service.credentials, nil
}

func TestListJSON(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{devices: []client.Device{{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}}},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"--format", "json", "list"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := stdout.String(); got == "" || got[0] != '[' {
		t.Fatalf("expected JSON array, got %q", got)
	}
}

func TestListWarnsOnPartialDiscoveryFailure(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{
			devices: []client.Device{{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}},
			listErr: transport.Wrap("discover nfc devices", errors.New("pcsc unavailable")),
		},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"list"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected device output")
	}
	if stderr.Len() == 0 {
		t.Fatal("expected warning output")
	}
}

func TestRawHuman(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{raw: &fidoctl.RawResult{Protocol: client.FamilyCTAP2, Command: 0x04, Response: []byte{0x00, 0xa1}}},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"raw", "--protocol", "ctap2", "--command", "0x04"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := stdout.String(); got != "ctap2 0x04 => 00a1\n" {
		t.Fatalf("unexpected output %q", got)
	}
}

func TestWriteCommandErrorJSON(t *testing.T) {
	stderr := &bytes.Buffer{}
	err := writeCommandError(stderr, "json", &ctap2.Error{Code: 0x12})
	if err != nil {
		t.Fatalf("writeCommandError() error = %v", err)
	}

	var payload commandErrorEnvelope
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error.Message != "ctap2: status 0x12: invalid CBOR" {
		t.Fatalf("message = %q", payload.Error.Message)
	}
	if payload.Error.ExitCode != exitProtocol {
		t.Fatalf("exitCode = %d, want %d", payload.Error.ExitCode, exitProtocol)
	}
	if payload.Error.Kind != "protocol" {
		t.Fatalf("kind = %q, want protocol", payload.Error.Kind)
	}
}

func TestInfoHumanIncludesCapabilitySummary(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{info: &fidoctl.InfoResult{
			Device: client.Device{ID: "device-1", Transport: transport.KindUSB, Manufacturer: "SafeNet", Product: "eToken Fusion", SerialNumber: "1234"},
			Capabilities: &client.Capabilities{RawCTAP2: &ctap2.GetInfoResponse{
				Versions:           []string{"FIDO_2_1", "FIDO_2_1_PRE"},
				Extensions:         []string{"credProtect", "hmac-secret"},
				AAGUID:             bytes.Repeat([]byte{0xAB}, 16),
				Options:            map[string]bool{"clientPin": true, "credMgmt": true},
				PinUVAuthProtocols: []uint64{2, 1},
				Transports:         []string{"usb", "nfc"},
			}},
			PINRetries: &client.PINRetries{PINRetries: 8, UVRetries: 5},
		}},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"info"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	output := stdout.String()
	for _, expected := range []string{"Device", "Preferred", "CTAP2 Versions", "PIN Retries", "Options:", "clientPin=true", "credMgmt=true"} {
		if !bytes.Contains(stdout.Bytes(), []byte(expected)) {
			t.Fatalf("output %q does not contain %q", output, expected)
		}
	}
}

func TestPinRetriesHuman(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{retries: &fidoctl.PINRetriesResult{
			Device:     client.Device{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"},
			PINRetries: &client.PINRetries{PINRetries: 8, UVRetries: 5},
		}},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"pin", "retries"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	output := stdout.String()
	for _, expected := range []string{"PIN Retries", "8", "UV Retries", "5"} {
		if !bytes.Contains(stdout.Bytes(), []byte(expected)) {
			t.Fatalf("output %q does not contain %q", output, expected)
		}
	}
}

func TestPinChangeReadsSecretsFromStdin(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	service := &fakeService{}
	command := newRootCommand(cliDependencies{
		service: service,
		stdin:   bytes.NewBufferString("12345678\n87654321\n"),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"pin", "change", "--old-pin-stdin", "--new-pin-stdin"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if service.changeCalls != 1 {
		t.Fatalf("changeCalls = %d, want 1", service.changeCalls)
	}
	if string(service.currentPIN) != "12345678" {
		t.Fatalf("currentPIN = %q, want 12345678", service.currentPIN)
	}
	if string(service.newPIN) != "87654321" {
		t.Fatalf("newPIN = %q, want 87654321", service.newPIN)
	}
	if got := stdout.String(); got != "PIN changed\n" {
		t.Fatalf("unexpected output %q", got)
	}
}

func TestPinSetReadsSecretFromStdin(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	service := &fakeService{}
	command := newRootCommand(cliDependencies{
		service: service,
		stdin:   bytes.NewBufferString("12345678\n"),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"pin", "set", "--new-pin-stdin"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if service.setCalls != 1 {
		t.Fatalf("setCalls = %d, want 1", service.setCalls)
	}
	if string(service.setPIN) != "12345678" {
		t.Fatalf("setPIN = %q, want 12345678", service.setPIN)
	}
	if got := stdout.String(); got != "PIN set\n" {
		t.Fatalf("unexpected output %q", got)
	}
}

func TestJSONFlagUsesJSONOutput(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{devices: []client.Device{{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}}},
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"--json", "devices"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := stdout.String(); got == "" || got[0] != '[' {
		t.Fatalf("expected JSON array, got %q", got)
	}
}

func TestResetRequiresYesWhenNonInteractive(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	service := &fakeService{}
	command := newRootCommand(cliDependencies{
		service: service,
		stdin:   bytes.NewBuffer(nil),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"--no-interactive", "reset"})

	err := command.Execute()
	if err == nil {
		t.Fatal("expected reset confirmation error")
	}
	if !errors.Is(err, errResetConfirmationRequired) {
		t.Fatalf("Execute() error = %v, want reset confirmation error", err)
	}
	if service.resetCalls != 0 {
		t.Fatalf("resetCalls = %d, want 0", service.resetCalls)
	}
}

func TestResetPromptsForInteractiveConfirmation(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	service := &fakeService{}
	command := newRootCommand(cliDependencies{
		service: service,
		stdin:   bytes.NewBufferString(resetConfirmationValue + "\n"),
		stdout:  stdout,
		stderr:  stderr,
		version: "test",
		flags:   &globalFlags{},
	})
	command.SetArgs([]string{"reset"})

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if service.resetCalls != 1 {
		t.Fatalf("resetCalls = %d, want 1", service.resetCalls)
	}
	if got := stdout.String(); got != "reset completed\n" {
		t.Fatalf("unexpected output %q", got)
	}
	if !bytes.Contains(stderr.Bytes(), []byte(resetConfirmationValue)) {
		t.Fatalf("expected confirmation prompt, got %q", stderr.String())
	}
	if classifyError(errResetConfirmationRequired) != exitUsageError {
		t.Fatalf("classifyError(reset confirmation) = %d, want %d", classifyError(errResetConfirmationRequired), exitUsageError)
	}
}
