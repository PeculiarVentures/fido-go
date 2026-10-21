package client_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
)

func TestDefaultCTAP1VersionUsesExtendedAPDU(t *testing.T) {
	t.Parallel()

	// USB U2F authenticators require extended APDU encoding, even without data.
	wantRequest := []byte{0, 3, 0, 0, 0, 0, 0}
	wantResponse := []byte{'U', '2', 'F', '_', 'V', '2', 0x90, 0}
	session := &mockSession{exchange: func(_ context.Context, request []byte) ([]byte, error) {
		if !bytes.Equal(request, wantRequest) {
			t.Fatalf("VERSION APDU = %x, want %x", request, wantRequest)
		}
		return wantResponse, nil
	}}
	sdk, err := client.New(session, client.WithDefaultRawInvokers())
	if err != nil {
		t.Fatal(err)
	}
	response, err := sdk.InvokeRaw(context.Background(), client.FamilyCTAP1, ctap1.CommandVersion, nil)
	if err != nil || !bytes.Equal(response, wantResponse) {
		t.Fatalf("InvokeRaw VERSION = %x, %v", response, err)
	}
	typed, err := ctap1.NewVersionCommand().Encode()
	if err != nil || !bytes.Equal(typed, wantRequest) {
		t.Fatalf("typed VERSION APDU = %x, %v", typed, err)
	}
	var version ctap1.VersionResponse
	if err := ctap1.NewVersionCommand().DecodeResponse(response, &version); err != nil || version.Version != "U2F_V2" {
		t.Fatalf("decoded VERSION = %q, %v", version.Version, err)
	}
}
