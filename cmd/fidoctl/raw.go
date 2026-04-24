package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

func newRawCommand(deps cliDependencies) *cobra.Command {
	var protocolFlag string
	var commandFlag string
	var payloadFlag string
	command := &cobra.Command{
		Use:   "raw",
		Short: "Send a raw CTAP command",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			family, err := parseProtocol(protocolFlag)
			if err != nil {
				return err
			}
			commandByte, err := parseCommand(commandFlag)
			if err != nil {
				return err
			}
			payload, err := decodeBinary(payloadFlag)
			if err != nil {
				return err
			}

			result, err := deps.service.Raw(ctx, fidoctl.RawRequest{
				DeviceID: deps.flags.deviceID,
				Protocol: family,
				Command:  commandByte,
				Payload:  payload,
			})
			if err != nil {
				return err
			}
			return writeRawValue(deps.stdout, deps.flags.format, result.Response, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "%s 0x%02x => %x\n", result.Protocol, result.Command, result.Response)
				return err
			})
		},
	}
	command.Flags().StringVar(&protocolFlag, "protocol", "ctap2", "Protocol family: ctap1 or ctap2")
	command.Flags().StringVar(&commandFlag, "command", "", "Command byte in decimal or hex")
	command.Flags().StringVar(&payloadFlag, "payload", "", "Hex or base64 payload")
	return command
}

func newTraceCommand(deps cliDependencies) *cobra.Command {
	var protocolFlag string
	var commandFlag string
	var payloadFlag string
	var unsafeIncludeSecrets bool
	command := &cobra.Command{
		Use:   "trace",
		Short: "Send a raw CTAP command with payload tracing",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			family, err := parseProtocol(protocolFlag)
			if err != nil {
				return err
			}
			commandByte, err := parseCommand(commandFlag)
			if err != nil {
				return err
			}
			payload, err := decodeBinary(payloadFlag)
			if err != nil {
				return err
			}

			result, err := deps.service.Trace(ctx, fidoctl.RawRequest{
				DeviceID:    deps.flags.deviceID,
				Protocol:    family,
				Command:     commandByte,
				Payload:     payload,
				UnsafeTrace: unsafeIncludeSecrets,
			})
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				for _, event := range result.Events {
					if event.Redacted {
						if _, err := fmt.Fprintf(writer, "%s command=0x%02x length=%d redacted\n", event.Direction, event.Command, event.Length); err != nil {
							return err
						}
						continue
					}
					if _, err := fmt.Fprintf(writer, "%s %x\n", event.Direction, event.Payload); err != nil {
						return err
					}
				}
				_, err := fmt.Fprintf(writer, "response %x\n", result.Response)
				return err
			})
		},
	}
	command.Flags().StringVar(&protocolFlag, "protocol", "ctap2", "Protocol family: ctap1 or ctap2")
	command.Flags().StringVar(&commandFlag, "command", "", "Command byte in decimal or hex")
	command.Flags().StringVar(&payloadFlag, "payload", "", "Hex or base64 payload")
	command.Flags().BoolVar(&unsafeIncludeSecrets, "unsafe-include-secrets", false, "Include sensitive raw payloads in trace output")
	return command
}

func parseProtocol(value string) (client.ProtocolFamily, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ctap1", "u2f":
		return client.FamilyCTAP1, nil
	case "ctap2":
		return client.FamilyCTAP2, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", value)
	}
}

func parseCommand(value string) (byte, error) {
	if value == "" {
		return 0, fmt.Errorf("command is required")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 8)
	if err == nil && strings.HasPrefix(strings.ToLower(value), "0x") {
		return byte(parsed), nil
	}
	parsed, err = strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid command %q", value)
	}
	return byte(parsed), nil
}

func decodeBinary(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.RawStdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid binary value %q", value)
}

func decodeOptionalBinary(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return decodeBinary(value)
}
