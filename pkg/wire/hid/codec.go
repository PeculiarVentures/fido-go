package hid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	// ErrPayloadTooLarge reports that a HID payload exceeds the framing limits.
	ErrPayloadTooLarge   = errors.New("payload too large")
	errInvalidReportSize = errors.New("invalid report size")
	errInvalidCommand    = errors.New("invalid HID command")
	errInvalidPacket     = errors.New("invalid packet")
	errMismatchedChannel = errors.New("mismatched channel")
	errUnexpectedCommand = errors.New("unexpected command")
	errUnexpectedSeq     = errors.New("unexpected continuation sequence")
	errIncompletePayload = errors.New("incomplete HID payload")
)

// Codec fragments and reassembles one HID-framed message stream.
type Codec struct {
	channel    uint32
	command    byte
	reportSize int
}

// Assembler incrementally reconstructs one HID response payload.
type Assembler struct {
	codec   *Codec
	started bool
	done    bool
	total   int
	nextSeq byte
	buffer  []byte
}

// NewCodec configures a HID codec for one channel and command byte.
func NewCodec(channel uint32, command byte, reportSize int) (*Codec, error) {
	if reportSize <= 7 {
		return nil, fmt.Errorf("wire/hid: %w", errInvalidReportSize)
	}
	if command&0x80 == 0 {
		return nil, fmt.Errorf("wire/hid: %w", errInvalidCommand)
	}
	return &Codec{channel: channel, command: command, reportSize: reportSize}, nil
}

// Fragment splits a payload into HID reports.
func (codec *Codec) Fragment(payload []byte) ([][]byte, error) {
	if len(payload) > maxPayloadSize(codec.reportSize) || len(payload) > math.MaxUint16 {
		return nil, fmt.Errorf("wire/hid: %w", ErrPayloadTooLarge)
	}

	packets := make([][]byte, 0, 1)
	initial := make([]byte, codec.reportSize)
	binary.BigEndian.PutUint32(initial[:4], codec.channel)
	initial[4] = codec.command
	binary.BigEndian.PutUint16(initial[5:7], uint16(len(payload)))
	firstSize := min(len(payload), codec.reportSize-7)
	copy(initial[7:], payload[:firstSize])
	packets = append(packets, initial)

	remaining := payload[firstSize:]
	sequence := byte(0)
	for len(remaining) > 0 {
		packet := make([]byte, codec.reportSize)
		binary.BigEndian.PutUint32(packet[:4], codec.channel)
		packet[4] = sequence
		chunkSize := min(len(remaining), codec.reportSize-5)
		copy(packet[5:], remaining[:chunkSize])
		packets = append(packets, packet)
		remaining = remaining[chunkSize:]
		sequence++
	}
	return packets, nil
}

// NewAssembler creates a fresh assembler for one response message.
func (codec *Codec) NewAssembler() *Assembler {
	return &Assembler{codec: codec, total: -1}
}

// Add validates one HID packet and appends its payload bytes.
func (assembler *Assembler) Add(packet []byte) error {
	if assembler.done {
		return fmt.Errorf("wire/hid: %w", errInvalidPacket)
	}
	if len(packet) != assembler.codec.reportSize {
		return fmt.Errorf("wire/hid: %w", errInvalidPacket)
	}
	if binary.BigEndian.Uint32(packet[:4]) != assembler.codec.channel {
		return fmt.Errorf("wire/hid: %w", errMismatchedChannel)
	}

	if !assembler.started {
		if packet[4] != assembler.codec.command {
			return fmt.Errorf("wire/hid: %w", errUnexpectedCommand)
		}
		assembler.started = true
		assembler.total = int(binary.BigEndian.Uint16(packet[5:7]))
		chunkSize := min(assembler.total, len(packet)-7)
		assembler.buffer = append(assembler.buffer, packet[7:7+chunkSize]...)
		assembler.done = len(assembler.buffer) >= assembler.total
		return nil
	}

	if packet[4] != assembler.nextSeq {
		return fmt.Errorf("wire/hid: %w", errUnexpectedSeq)
	}
	assembler.nextSeq++
	remaining := assembler.total - len(assembler.buffer)
	chunkSize := min(remaining, len(packet)-5)
	assembler.buffer = append(assembler.buffer, packet[5:5+chunkSize]...)
	assembler.done = len(assembler.buffer) >= assembler.total
	return nil
}

// Done reports whether the full message has been assembled.
func (assembler *Assembler) Done() bool {
	return assembler.done
}

// Payload returns the reconstructed payload once all packets were received.
func (assembler *Assembler) Payload() ([]byte, error) {
	if !assembler.done {
		return nil, fmt.Errorf("wire/hid: %w", errIncompletePayload)
	}
	return append([]byte(nil), assembler.buffer[:assembler.total]...), nil
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxPayloadSize(reportSize int) int {
	const maxContinuationPackets = 128
	return (reportSize - 7) + maxContinuationPackets*(reportSize-5)
}
