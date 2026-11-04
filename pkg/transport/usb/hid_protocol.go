package usb

import (
	"context"
	"encoding/binary"
	"fmt"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func readHIDMessage(ctx context.Context, reportSize int, channelID uint32, command byte, readPacket func(context.Context) ([]byte, error)) ([]byte, error) {
	codec, err := wirehid.NewCodec(channelID, command, reportSize)
	if err != nil {
		return nil, err
	}
	// HID input can contain late reports from a retired session or traffic
	// for another client. Filter by CID before assembling this response.
	readPacket = hidChannelReader(reportSize, channelID, readPacket)
	assembler := codec.NewAssembler()
	firstPacket := true
	for !assembler.Done() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		packet, err := readPacket(ctx)
		if err != nil {
			return nil, err
		}
		if firstPacket && isHIDKeepalivePacket(packet, reportSize, channelID) {
			if err := discardHIDMessage(ctx, reportSize, channelID, hidCommandKeepalive, packet, readPacket); err != nil {
				return nil, err
			}
			continue
		}
		if firstPacket && isHIDCommandPacket(packet, reportSize, channelID, hidCommandError) {
			return nil, readHIDError(ctx, reportSize, channelID, packet, readPacket)
		}
		if err := assembler.Add(packet); err != nil {
			return nil, err
		}
		firstPacket = false
	}
	return assembler.Payload()
}

func discardHIDMessage(ctx context.Context, reportSize int, channelID uint32, command byte, firstPacket []byte, readPacket func(context.Context) ([]byte, error)) error {
	codec, err := wirehid.NewCodec(channelID, command, reportSize)
	if err != nil {
		return err
	}
	assembler := codec.NewAssembler()
	if err := assembler.Add(firstPacket); err != nil {
		return err
	}
	for !assembler.Done() {
		if err := ctx.Err(); err != nil {
			return err
		}
		packet, err := readPacket(ctx)
		if err != nil {
			return err
		}
		if err := assembler.Add(packet); err != nil {
			return err
		}
	}
	_, err = assembler.Payload()
	return err
}

func isHIDKeepalivePacket(packet []byte, reportSize int, channelID uint32) bool {
	return isHIDCommandPacket(packet, reportSize, channelID, hidCommandKeepalive)
}

func isHIDCommandPacket(packet []byte, reportSize int, channelID uint32, command byte) bool {
	if len(packet) != reportSize {
		return false
	}
	if binary.BigEndian.Uint32(packet[:4]) != channelID {
		return false
	}
	return packet[4] == command
}

func readHIDError(ctx context.Context, reportSize int, channelID uint32, firstPacket []byte, readPacket func(context.Context) ([]byte, error)) error {
	codec, err := wirehid.NewCodec(channelID, hidCommandError, reportSize)
	if err != nil {
		return err
	}
	assembler := codec.NewAssembler()
	if err := assembler.Add(firstPacket); err != nil {
		return err
	}
	for !assembler.Done() {
		if err := ctx.Err(); err != nil {
			return err
		}
		packet, err := readPacket(ctx)
		if err != nil {
			return err
		}
		if err := assembler.Add(packet); err != nil {
			return err
		}
	}
	payload, err := assembler.Payload()
	if err != nil {
		return err
	}
	if len(payload) != 1 {
		return fmt.Errorf("transport/usb: invalid CTAPHID error payload length %d", len(payload))
	}
	return &HIDError{Code: payload[0]}
}
