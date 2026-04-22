package nfc

import (
	"errors"
	"fmt"
)

var (
	errInvalidChunkSize = errors.New("invalid APDU chunk size")
	errInvalidResponse  = errors.New("invalid APDU response")
	errStatusWord       = errors.New("unexpected APDU status word")
	errIncompleteAPDU   = errors.New("incomplete APDU response")
)

const getResponseInstruction byte = 0xC0

// Codec wraps and unwraps NFC APDU frames without interpreting CTAP semantics.
type Codec struct {
	class        byte
	instruction  byte
	parameter1   byte
	parameter2   byte
	maxChunkSize int
}

// Assembler incrementally reconstructs an APDU response body.
type Assembler struct {
	done         bool
	buffer       []byte
	moreDataHint byte
}

// NewCodec configures an APDU codec for one command header.
func NewCodec(class, instruction, parameter1, parameter2 byte, maxChunkSize int) (*Codec, error) {
	if maxChunkSize <= 0 || maxChunkSize > 255 {
		return nil, fmt.Errorf("wire/nfc: %w", errInvalidChunkSize)
	}
	return &Codec{class: class, instruction: instruction, parameter1: parameter1, parameter2: parameter2, maxChunkSize: maxChunkSize}, nil
}

// Fragment splits a payload into APDU command packets and sets the chain bit as needed.
func (codec *Codec) Fragment(payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return [][]byte{{codec.class, codec.instruction, codec.parameter1, codec.parameter2, 0x00}}, nil
	}

	packets := make([][]byte, 0, 1)
	remaining := payload
	for len(remaining) > 0 {
		chunkSize := minNFC(len(remaining), codec.maxChunkSize)
		cla := codec.class
		if chunkSize != len(remaining) {
			cla |= 0x10
		}
		packet := []byte{cla, codec.instruction, codec.parameter1, codec.parameter2, byte(chunkSize)}
		packet = append(packet, remaining[:chunkSize]...)
		packets = append(packets, packet)
		remaining = remaining[chunkSize:]
	}
	return packets, nil
}

// NewAssembler creates a fresh APDU response assembler.
func (codec *Codec) NewAssembler() *Assembler {
	return &Assembler{}
}

// ValidateInterimResponse checks that an intermediate chained-command response is success-only.
func (codec *Codec) ValidateInterimResponse(response []byte) error {
	if len(response) != 2 || response[0] != 0x90 || response[1] != 0x00 {
		return fmt.Errorf("wire/nfc: %w", errStatusWord)
	}
	return nil
}

// GetResponsePacket creates a GET RESPONSE APDU using the latest SW2 hint.
func (codec *Codec) GetResponsePacket(expectedLength byte) []byte {
	return []byte{codec.class, getResponseInstruction, 0x00, 0x00, expectedLength}
}

// Add validates one APDU response packet and appends its body bytes.
func (assembler *Assembler) Add(response []byte) error {
	if len(response) < 2 {
		return fmt.Errorf("wire/nfc: %w", errInvalidResponse)
	}
	status1 := response[len(response)-2]
	status2 := response[len(response)-1]
	assembler.buffer = append(assembler.buffer, response[:len(response)-2]...)

	switch {
	case status1 == 0x90 && status2 == 0x00:
		assembler.done = true
		assembler.moreDataHint = 0
		return nil
	case status1 == 0x61:
		assembler.done = false
		assembler.moreDataHint = status2
		return nil
	default:
		return fmt.Errorf("wire/nfc: %w", errStatusWord)
	}
}

// Done reports whether the full APDU response body was assembled.
func (assembler *Assembler) Done() bool {
	return assembler.done
}

// MoreDataHint returns the SW2 hint for the next GET RESPONSE packet.
func (assembler *Assembler) MoreDataHint() byte {
	return assembler.moreDataHint
}

// Payload returns the reconstructed APDU body once the final status word was received.
func (assembler *Assembler) Payload() ([]byte, error) {
	if !assembler.done {
		return nil, fmt.Errorf("wire/nfc: %w", errIncompleteAPDU)
	}
	return append([]byte(nil), assembler.buffer...), nil
}

func minNFC(left, right int) int {
	if left < right {
		return left
	}
	return right
}
