package ble

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	// ErrPayloadTooLarge reports that a BLE payload cannot fit into the 16-bit length field.
	ErrPayloadTooLarge = errors.New("payload too large")
	errInvalidMTU      = errors.New("invalid mtu")
	errInvalidFragment = errors.New("invalid fragment")
	errIncompleteValue = errors.New("incomplete BLE payload")
)

// Codec fragments and reassembles one BLE message stream.
type Codec struct {
	mtu int
}

// Assembler incrementally reconstructs one BLE response payload.
type Assembler struct {
	codec   *Codec
	started bool
	done    bool
	total   int
	buffer  []byte
}

// NewCodec configures a BLE codec for one MTU.
func NewCodec(mtu int) (*Codec, error) {
	if mtu <= 2 {
		return nil, fmt.Errorf("wire/ble: %w", errInvalidMTU)
	}
	return &Codec{mtu: mtu}, nil
}

// Fragment splits a payload into BLE-sized fragments.
func (codec *Codec) Fragment(payload []byte) ([][]byte, error) {
	if len(payload) > math.MaxUint16 {
		return nil, fmt.Errorf("wire/ble: %w", ErrPayloadTooLarge)
	}

	firstSize := minBLE(len(payload), codec.mtu-2)
	first := make([]byte, 2+firstSize)
	binary.BigEndian.PutUint16(first[:2], uint16(len(payload)))
	copy(first[2:], payload[:firstSize])
	fragments := [][]byte{first}

	remaining := payload[firstSize:]
	for len(remaining) > 0 {
		chunkSize := minBLE(len(remaining), codec.mtu)
		fragment := append([]byte(nil), remaining[:chunkSize]...)
		fragments = append(fragments, fragment)
		remaining = remaining[chunkSize:]
	}
	return fragments, nil
}

// NewAssembler creates a fresh assembler for one BLE message.
func (codec *Codec) NewAssembler() *Assembler {
	return &Assembler{codec: codec, total: -1}
}

// Add validates one BLE fragment and appends its bytes.
//
// BLE ordering is guaranteed by the transport/backend. The codec validates only
// fragment size and the declared aggregate length.
func (assembler *Assembler) Add(fragment []byte) error {
	if assembler.done {
		return fmt.Errorf("wire/ble: %w", errInvalidFragment)
	}
	if len(fragment) > assembler.codec.mtu {
		return fmt.Errorf("wire/ble: %w", errInvalidFragment)
	}

	if !assembler.started {
		if len(fragment) < 2 {
			return fmt.Errorf("wire/ble: %w", errInvalidFragment)
		}
		assembler.started = true
		assembler.total = int(binary.BigEndian.Uint16(fragment[:2]))
		chunkSize := minBLE(assembler.total, len(fragment)-2)
		assembler.buffer = append(assembler.buffer, fragment[2:2+chunkSize]...)
		assembler.done = len(assembler.buffer) >= assembler.total
		return nil
	}

	remaining := assembler.total - len(assembler.buffer)
	chunkSize := minBLE(remaining, len(fragment))
	assembler.buffer = append(assembler.buffer, fragment[:chunkSize]...)
	assembler.done = len(assembler.buffer) >= assembler.total
	return nil
}

// Done reports whether the payload is fully assembled.
func (assembler *Assembler) Done() bool {
	return assembler.done
}

// Payload returns the reconstructed payload once assembly is complete.
func (assembler *Assembler) Payload() ([]byte, error) {
	if !assembler.done {
		return nil, fmt.Errorf("wire/ble: %w", errIncompleteValue)
	}
	return append([]byte(nil), assembler.buffer[:assembler.total]...), nil
}

func minBLE(left, right int) int {
	if left < right {
		return left
	}
	return right
}
