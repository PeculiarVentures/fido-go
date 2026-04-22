package ctap2_test

import (
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

func TestResetCommandEncodeDecode(t *testing.T) {
	t.Parallel()

	command := ctap2.NewResetCommand()
	encoded, err := command.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != 1 || encoded[0] != ctap2.CommandReset {
		t.Fatalf("unexpected reset encoding: % X", encoded)
	}

	var response ctap2.ResetResponse
	if err := command.DecodeResponse([]byte{0x00}, &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
