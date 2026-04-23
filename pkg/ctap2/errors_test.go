package ctap2

import "testing"

func TestStatusTextIncludesKnownCTAP2Statuses(t *testing.T) {
	tests := []struct {
		code uint8
		want string
	}{
		{code: 0x12, want: "invalid CBOR"},
		{code: 0x3e, want: "invalid subcommand"},
		{code: 0x40, want: "unauthorized permission"},
	}

	for _, test := range tests {
		if got := statusText(test.code); got != test.want {
			t.Fatalf("statusText(0x%02x) = %q, want %q", test.code, got, test.want)
		}
	}
}

func TestErrorUsesMappedStatusText(t *testing.T) {
	err := (&Error{Code: 0x12}).Error()
	if err != "ctap2: status 0x12: invalid CBOR" {
		t.Fatalf("Error() = %q", err)
	}
}
