package ctap2

import (
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var ctap2EncMode = mustCTAP2EncMode()

func encodeCommand(command byte, request any) ([]byte, error) {
	if request == nil {
		return []byte{command}, nil
	}

	encoded, err := ctap2EncMode.Marshal(request)
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

// DecodeInto validates a DecodeResponse target and returns it as the expected type.
func DecodeInto[T any](response any, operation string) (*T, error) {
	target, ok := response.(*T)
	if !ok || target == nil {
		typeName := "*" + reflect.TypeFor[T]().String()
		if operation == "" {
			return nil, fmt.Errorf("ctap2: response target must be %s", typeName)
		}
		return nil, fmt.Errorf("ctap2: %s response target must be %s", operation, typeName)
	}
	return target, nil
}

func mustCTAP2EncMode() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("ctap2: create CTAP2 CBOR encoder: %v", err))
	}
	return mode
}
