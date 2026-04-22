package ctap1

import "fmt"

const (
	maxShortResponseLength    uint32 = 256
	maxExtendedResponseLength uint32 = 65536
)

// EncodeShortAPDU encodes a CTAP1 command using the short APDU form.
func EncodeShortAPDU(command byte, data []byte) ([]byte, error) {
	return encodeAPDU(command, 0x00, 0x00, data, maxShortResponseLength)
}

// EncodeAPDU encodes a CTAP1 command with explicit P1 and P2 values.
func EncodeAPDU(command, p1, p2 byte, data []byte) ([]byte, error) {
	return encodeAPDU(command, p1, p2, data, maxExtendedResponseLength)
}

func encodeAPDU(command, p1, p2 byte, data []byte, maxResponseLength uint32) ([]byte, error) {
	if maxResponseLength > maxExtendedResponseLength {
		return nil, fmt.Errorf("ctap1: unsupported response length %d", maxResponseLength)
	}
	if len(data) > 0xffff {
		return nil, fmt.Errorf("ctap1: APDU payload exceeds extended encoding limit: %d", len(data))
	}

	if len(data) <= 0xff && maxResponseLength <= maxShortResponseLength {
		return encodeShortAPDU(command, p1, p2, data, maxResponseLength)
	}
	return encodeExtendedAPDU(command, p1, p2, data, maxResponseLength)
}

func encodeShortAPDU(command, p1, p2 byte, data []byte, maxResponseLength uint32) ([]byte, error) {
	encoded := []byte{0x00, command, p1, p2}
	if len(data) > 0 {
		encoded = append(encoded, byte(len(data)))
		encoded = append(encoded, data...)
	}
	if maxResponseLength > 0 {
		le := byte(maxResponseLength)
		if maxResponseLength == maxShortResponseLength {
			le = 0x00
		}
		encoded = append(encoded, le)
	}
	return encoded, nil
}

func encodeExtendedAPDU(command, p1, p2 byte, data []byte, maxResponseLength uint32) ([]byte, error) {
	encoded := []byte{0x00, command, p1, p2, 0x00}
	if len(data) > 0 {
		encoded = append(encoded, byte(len(data)>>8), byte(len(data)))
		encoded = append(encoded, data...)
	}
	if maxResponseLength > 0 {
		le := maxResponseLength
		if maxResponseLength == maxExtendedResponseLength {
			le = 0
		}
		encoded = append(encoded, byte(le>>8), byte(le))
	}
	return encoded, nil
}

func decodeResponse(data []byte) ([]byte, uint16, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("ctap1: response is too short")
	}

	statusWord := uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])
	payload := data[:len(data)-2]
	if statusWord != successStatusWord {
		return nil, statusWord, &Error{StatusWord: statusWord}
	}
	return payload, statusWord, nil
}
