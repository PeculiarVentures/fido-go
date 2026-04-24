package protocol_test

import (
	"errors"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

func TestFamilyValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		family  protocol.Family
		wantErr bool
	}{
		{name: "ctap1", family: protocol.FamilyCTAP1},
		{name: "ctap2", family: protocol.FamilyCTAP2},
		{name: "unknown", family: protocol.Family("u2f"), wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.family.Validate()
			if test.wantErr {
				var unknownErr *protocol.UnknownFamilyError
				if !errors.As(err, &unknownErr) {
					t.Fatalf("expected UnknownFamilyError, got %v", err)
				}
				if unknownErr.Error() != "protocol: unknown family \"u2f\"" {
					t.Fatalf("unexpected error message: %q", unknownErr.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}
