package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

const (
	exitSuccess      = 0
	exitGeneralError = 1
	exitUsageError   = 2
	exitDeviceError  = 3
	exitTimeout      = 4
	exitProtocol     = 5
)

var version = "dev"

type globalFlags struct {
	deviceID      string
	timeout       time.Duration
	format        string
	verbose       bool
	debug         bool
	noInteractive bool
}

type cliDependencies struct {
	service fidoctl.Service
	stdout  io.Writer
	stderr  io.Writer
	version string
	flags   *globalFlags
}

type interactionConfigurer interface {
	ConfigureInteraction(interactive bool, status io.Writer)
}

func main() {
	service, err := fidoctl.NewDefault()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitGeneralError)
	}
	command := newRootCommand(cliDependencies{
		service: service,
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		version: version,
		flags:   &globalFlags{},
	})
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(classifyError(err))
	}
	os.Exit(exitSuccess)
}

func newRootCommand(deps cliDependencies) *cobra.Command {
	root := &cobra.Command{
		Use:           "fidoctl",
		Short:         "FIDO authenticator command-line interface",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if configurer, ok := deps.service.(interactionConfigurer); ok {
				configurer.ConfigureInteraction(!deps.flags.noInteractive, deps.stderr)
			}
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	root.PersistentFlags().StringVar(&deps.flags.deviceID, "device-id", "", "Select a specific device; defaults to the first discovered authenticator")
	root.PersistentFlags().DurationVar(&deps.flags.timeout, "timeout", 30*time.Second, "Command timeout")
	root.PersistentFlags().StringVar(&deps.flags.format, "format", "human", "Output format: human, json, raw")
	root.PersistentFlags().BoolVar(&deps.flags.verbose, "verbose", false, "Enable verbose output")
	root.PersistentFlags().BoolVar(&deps.flags.debug, "debug", false, "Enable debug output")
	root.PersistentFlags().BoolVar(&deps.flags.noInteractive, "no-interactive", false, "Disable interactive prompts")

	root.AddCommand(
		newListCommand(deps),
		newInfoCommand(deps),
		newRawCommand(deps),
		newTraceCommand(deps),
		newRegisterCommand(deps),
		newAuthenticateCommand(deps),
		newResetCommand(deps),
		newCredsCommand(deps),
		newVersionCommand(deps),
	)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func newListCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List discovered authenticators",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			devices, err := deps.service.ListDevices(ctx)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, devices, func(writer io.Writer) error {
				if len(devices) == 0 {
					_, err := fmt.Fprintln(writer, "No devices found")
					return err
				}
				for _, device := range devices {
					if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", device.ID, device.Transport, device.DisplayName()); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newInfoCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show capabilities for one authenticator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			result, err := deps.service.Info(ctx, deps.flags.deviceID)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				preferred, _ := result.Capabilities.PreferredProtocol()
				_, err := fmt.Fprintf(writer, "%s\tpreferred=%s\n", result.Device.DisplayName(), preferred)
				return err
			})
		},
	}
}

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
				DeviceID: deps.flags.deviceID,
				Protocol: family,
				Command:  commandByte,
				Payload:  payload,
			})
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				for _, event := range result.Events {
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
	return command
}

func newRegisterCommand(deps cliDependencies) *cobra.Command {
	var challengeFlag string
	var rpIDFlag string
	var rpNameFlag string
	var userIDFlag string
	var userNameFlag string
	var userDisplayNameFlag string
	var appIDHashFlag string
	command := &cobra.Command{
		Use:   "register",
		Short: "Run a basic registration flow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			challengeHash, err := decodeBinary(challengeFlag)
			if err != nil {
				return err
			}
			userID, err := decodeBinary(userIDFlag)
			if err != nil {
				return err
			}
			appIDHash, err := decodeOptionalBinary(appIDHashFlag)
			if err != nil {
				return err
			}

			result, err := deps.service.Register(ctx, deps.flags.deviceID, client.RegisterRequest{
				ChallengeHash:   challengeHash,
				RPID:            rpIDFlag,
				RPName:          rpNameFlag,
				UserID:          userID,
				UserName:        userNameFlag,
				UserDisplayName: userDisplayNameFlag,
				AppIDHash:       appIDHash,
			})
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "registration completed via %s\n", result.Protocol)
				return err
			})
		},
	}
	command.Flags().StringVar(&challengeFlag, "challenge", "", "Challenge hash in hex or base64")
	command.Flags().StringVar(&rpIDFlag, "rp-id", "", "Relying party identifier")
	command.Flags().StringVar(&rpNameFlag, "rp-name", "", "Relying party display name")
	command.Flags().StringVar(&userIDFlag, "user-id", "", "User identifier in hex or base64")
	command.Flags().StringVar(&userNameFlag, "user-name", "", "User name")
	command.Flags().StringVar(&userDisplayNameFlag, "user-display-name", "", "User display name")
	command.Flags().StringVar(&appIDHashFlag, "app-id-hash", "", "CTAP1 app id hash in hex or base64")
	return command
}

func newAuthenticateCommand(deps cliDependencies) *cobra.Command {
	var challengeFlag string
	var rpIDFlag string
	var appIDHashFlag string
	var keyHandleFlag string
	command := &cobra.Command{
		Use:   "authenticate",
		Short: "Run a basic authentication flow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			challengeHash, err := decodeBinary(challengeFlag)
			if err != nil {
				return err
			}
			appIDHash, err := decodeOptionalBinary(appIDHashFlag)
			if err != nil {
				return err
			}
			keyHandle, err := decodeOptionalBinary(keyHandleFlag)
			if err != nil {
				return err
			}

			result, err := deps.service.Authenticate(ctx, deps.flags.deviceID, client.AuthenticateRequest{
				ChallengeHash: challengeHash,
				RPID:          rpIDFlag,
				AppIDHash:     appIDHash,
				KeyHandle:     keyHandle,
			})
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "authentication completed via %s\n", result.Protocol)
				return err
			})
		},
	}
	command.Flags().StringVar(&challengeFlag, "challenge", "", "Challenge hash in hex or base64")
	command.Flags().StringVar(&rpIDFlag, "rp-id", "", "Relying party identifier")
	command.Flags().StringVar(&appIDHashFlag, "app-id-hash", "", "CTAP1 app id hash in hex or base64")
	command.Flags().StringVar(&keyHandleFlag, "key-handle", "", "CTAP1 key handle in hex or base64")
	return command
}

func newResetCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset a CTAP2 authenticator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			if err := deps.service.Reset(ctx, deps.flags.deviceID); err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, map[string]bool{"reset": true}, func(writer io.Writer) error {
				_, err := fmt.Fprintln(writer, "reset completed")
				return err
			})
		},
	}
}

func newCredsCommand(deps cliDependencies) *cobra.Command {
	creds := &cobra.Command{Use: "creds", Short: "Manage discoverable credentials"}
	var pin string
	list := &cobra.Command{
		Use:   "list",
		Short: "List discoverable credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			result, err := deps.service.ListCredentials(ctx, deps.flags.deviceID, pin)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				if result.Credentials == nil || len(result.Credentials.Credentials) == 0 {
					_, err := fmt.Fprintln(writer, "No discoverable credentials found")
					return err
				}
				for _, credential := range result.Credentials.Credentials {
					name := credential.User.Name
					if name == "" {
						name = hex.EncodeToString(credential.User.ID)
					}
					if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", credential.RP.ID, name, hex.EncodeToString(credential.Credential.ID)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&pin, "pin", "", "Authenticator PIN")
	_ = list.MarkFlagRequired("pin")
	creds.AddCommand(list)
	return creds
}

func newVersionCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			result := map[string]string{"binary": "fidoctl", "version": deps.version}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintln(writer, deps.version)
				return err
			})
		},
	}
}

func withTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
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

func writeValue(writer io.Writer, format string, value any, human func(io.Writer) error) error {
	switch format {
	case "human":
		return human(writer)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeRawValue(writer io.Writer, format string, raw []byte, value any, human func(io.Writer) error) error {
	if format == "raw" {
		_, err := writer.Write(raw)
		return err
	}
	return writeValue(writer, format, value, human)
}

func classifyError(err error) int {
	var deviceErr *client.DeviceNotFoundError
	switch {
	case errors.As(err, &deviceErr):
		return exitDeviceError
	case errors.Is(err, context.DeadlineExceeded):
		return exitTimeout
	case strings.Contains(strings.ToLower(err.Error()), "ctap"):
		return exitProtocol
	case errors.Is(err, client.ErrPINRequired):
		return exitUsageError
	default:
		return exitGeneralError
	}
}
