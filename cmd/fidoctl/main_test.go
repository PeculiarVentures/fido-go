package main

import (
	"bytes"
	"context"
	"testing"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

type fakeService struct {
	devices     []client.Device
	info        *fidoctl.InfoResult
	raw         *fidoctl.RawResult
	credentials *fidoctl.CredentialListResult
}

func (service *fakeService) ListDevices(context.Context) ([]client.Device, error) {
	return service.devices, nil
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

func (service *fakeService) Register(context.Context, string, client.RegisterRequest) (*client.RegistrationResult, error) {
	return &client.RegistrationResult{Protocol: client.FamilyCTAP2}, nil
}

func (service *fakeService) Authenticate(context.Context, string, client.AuthenticateRequest) (*client.AssertionResult, error) {
	return &client.AssertionResult{Protocol: client.FamilyCTAP2}, nil
}

func (service *fakeService) Reset(context.Context, string) error {
	return nil
}

func (service *fakeService) ListCredentials(context.Context, string, string) (*fidoctl.CredentialListResult, error) {
	return service.credentials, nil
}

func TestListJSON(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{devices: []client.Device{{ID: "device-1", Transport: transport.KindUSB, Product: "YubiKey"}}},
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

func TestRawHuman(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newRootCommand(cliDependencies{
		service: &fakeService{raw: &fidoctl.RawResult{Protocol: client.FamilyCTAP2, Command: 0x04, Response: []byte{0x00, 0xa1}}},
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
