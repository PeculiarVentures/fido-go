package ctap2

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

func encodeCommand(command byte, request any) ([]byte, error) {
	if request == nil {
		return []byte{command}, nil
	}

	encoded, err := cbor.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("ctap2: encode command 0x%02x: %w", command, err)
	}
	return append([]byte{command}, encoded...), nil
}

func decodeCommandResponse(data []byte, response any) error {
	if len(data) == 0 {
		return fmt.Errorf("ctap2: response is empty")
	}
	if data[0] != 0x00 {
		return &Error{Code: data[0]}
	}
	if len(data) == 1 {
		return nil
	}
	if response == nil {
		return nil
	}
	if err := cbor.Unmarshal(data[1:], response); err != nil {
		return fmt.Errorf("ctap2: decode response: %w", err)
	}
	return nil
}
