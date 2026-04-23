package usb

import "testing"

func TestHIDCommandForRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     []byte
		command byte
	}{
		{
			name:    "ctap1 version short apdu",
			req:     []byte{0x00, 0x03, 0x00, 0x00},
			command: hidCommandMsg,
		},
		{
			name:    "ctap1 authenticate apdu",
			req:     []byte{0x00, 0x02, 0x03, 0x00, 0x00},
			command: hidCommandMsg,
		},
		{
			name:    "ctap2 getInfo",
			req:     []byte{0x04},
			command: hidCommandCBOR,
		},
		{
			name:    "ctap2 clientPIN",
			req:     []byte{0x06, 0xa1, 0x01, 0x01},
			command: hidCommandCBOR,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := hidCommandForRequest(test.req); got != test.command {
				t.Fatalf("hidCommandForRequest(%x) = 0x%02x, want 0x%02x", test.req, got, test.command)
			}
		})
	}
}
