package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
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

type application struct {
	locator client.Locator
}

type commonFlags struct {
	deviceID      string
	timeout       time.Duration
	format        string
	verbose       bool
	debug         bool
	noInteractive bool
}

func main() {
	locator, err := client.NewTransportLocator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitGeneralError)
	}
	app := &application{locator: locator}
	os.Exit(app.run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func (app *application) run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeRootUsage(stderr)
		return exitUsageError
	}

	var err error
	switch args[0] {
	case "list":
		err = app.runList(ctx, args[1:], stdout)
	case "info":
		err = app.runInfo(ctx, args[1:], stdout)
	case "raw":
		err = app.runRaw(ctx, args[1:], stdout)
	case "register":
		err = app.runRegister(ctx, args[1:], stdout)
	case "authenticate":
		err = app.runAuthenticate(ctx, args[1:], stdout)
	case "reset":
		err = app.runReset(ctx, args[1:], stdout)
	case "trace":
		err = app.runTrace(ctx, args[1:], stdout)
	case "version":
		_, err = fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		writeRootUsage(stdout)
		return exitSuccess
	default:
		fmt.Fprintf(stderr, "Error: unknown command %q\n", args[0])
		writeRootUsage(stderr)
		return exitUsageError
	}

	if err == nil {
		return exitSuccess
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitSuccess
	}
	fmt.Fprintf(stderr, "Error: %v\n", err)
	return classifyError(err)
}

func (app *application) runList(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	devices, err := app.locator.List(commandCtx)
	if err != nil {
		return err
	}
	return writeValue(stdout, common.format, devices, func(writer io.Writer) error {
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
}

func (app *application) runInfo(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("info")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	candidate, closeClient, err := app.openClient(commandCtx, common)
	if err != nil {
		return err
	}
	defer closeClient()

	caps, err := candidate.GetCapabilities(commandCtx)
	if err != nil {
		return err
	}
	result := struct {
		Device       client.Device              `json:"device"`
		Capabilities *client.DeviceCapabilities `json:"capabilities"`
	}{Device: candidate.Device(), Capabilities: caps}
	return writeValue(stdout, common.format, result, func(writer io.Writer) error {
		_, err := fmt.Fprintf(writer, "%s\tpreferred=%v\n", result.Device.DisplayName(), preferredProtocol(caps))
		return err
	})
}

func (app *application) runRaw(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("raw")
	protocolFlag := flags.String("protocol", "ctap2", "Protocol family: ctap1 or ctap2")
	commandFlag := flags.String("command", "", "Command byte in decimal or hex")
	payloadFlag := flags.String("payload", "", "Hex or base64 payload")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	family, err := parseProtocol(*protocolFlag)
	if err != nil {
		return err
	}
	command, err := parseCommand(*commandFlag)
	if err != nil {
		return err
	}
	payload, err := decodeBinary(*payloadFlag)
	if err != nil {
		return err
	}

	candidate, closeClient, err := app.openClient(commandCtx, common)
	if err != nil {
		return err
	}
	defer closeClient()

	response, err := candidate.InvokeRaw(commandCtx, family, command, payload)
	if err != nil {
		return err
	}
	result := struct {
		Protocol client.ProtocolFamily `json:"protocol"`
		Command  byte                  `json:"command"`
		Response []byte                `json:"response"`
	}{Protocol: family, Command: command, Response: response}
	return writeRawValue(stdout, common.format, response, result, func(writer io.Writer) error {
		_, err := fmt.Fprintf(writer, "%s 0x%02x => %x\n", family, command, response)
		return err
	})
}

func (app *application) runRegister(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("register")
	challengeFlag := flags.String("challenge", "", "Challenge hash in hex or base64")
	rpIDFlag := flags.String("rp-id", "", "Relying party identifier")
	rpNameFlag := flags.String("rp-name", "", "Relying party display name")
	userIDFlag := flags.String("user-id", "", "User identifier in hex or base64")
	userNameFlag := flags.String("user-name", "", "User name")
	userDisplayNameFlag := flags.String("user-display-name", "", "User display name")
	appIDHashFlag := flags.String("app-id-hash", "", "CTAP1 app id hash in hex or base64")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	challengeHash, err := decodeBinary(*challengeFlag)
	if err != nil {
		return err
	}
	userID, err := decodeBinary(*userIDFlag)
	if err != nil {
		return err
	}
	appIDHash, err := decodeOptionalBinary(*appIDHashFlag)
	if err != nil {
		return err
	}

	candidate, closeClient, err := app.openClient(commandCtx, common)
	if err != nil {
		return err
	}
	defer closeClient()

	result, err := candidate.Register(commandCtx, client.RegisterRequest{
		ChallengeHash:   challengeHash,
		RPID:            *rpIDFlag,
		RPName:          *rpNameFlag,
		UserID:          userID,
		UserName:        *userNameFlag,
		UserDisplayName: *userDisplayNameFlag,
		AppIDHash:       appIDHash,
	})
	if err != nil {
		return err
	}
	return writeValue(stdout, common.format, result, func(writer io.Writer) error {
		_, err := fmt.Fprintf(writer, "registration completed via %s\n", result.Protocol)
		return err
	})
}

func (app *application) runAuthenticate(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("authenticate")
	challengeFlag := flags.String("challenge", "", "Challenge hash in hex or base64")
	rpIDFlag := flags.String("rp-id", "", "Relying party identifier")
	appIDHashFlag := flags.String("app-id-hash", "", "CTAP1 app id hash in hex or base64")
	keyHandleFlag := flags.String("key-handle", "", "CTAP1 key handle in hex or base64")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	challengeHash, err := decodeBinary(*challengeFlag)
	if err != nil {
		return err
	}
	appIDHash, err := decodeOptionalBinary(*appIDHashFlag)
	if err != nil {
		return err
	}
	keyHandle, err := decodeOptionalBinary(*keyHandleFlag)
	if err != nil {
		return err
	}

	candidate, closeClient, err := app.openClient(commandCtx, common)
	if err != nil {
		return err
	}
	defer closeClient()

	result, err := candidate.Authenticate(commandCtx, client.AuthenticateRequest{
		ChallengeHash: challengeHash,
		RPID:          *rpIDFlag,
		AppIDHash:     appIDHash,
		KeyHandle:     keyHandle,
	})
	if err != nil {
		return err
	}
	return writeValue(stdout, common.format, result, func(writer io.Writer) error {
		_, err := fmt.Fprintf(writer, "authentication completed via %s\n", result.Protocol)
		return err
	})
}

func (app *application) runReset(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("reset")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	candidate, closeClient, err := app.openClient(commandCtx, common)
	if err != nil {
		return err
	}
	defer closeClient()

	if err := candidate.Reset(commandCtx); err != nil {
		return err
	}
	return writeValue(stdout, common.format, map[string]bool{"reset": true}, func(writer io.Writer) error {
		_, err := fmt.Fprintln(writer, "reset completed")
		return err
	})
}

func (app *application) runTrace(ctx context.Context, args []string, stdout io.Writer) error {
	flags, common := newFlagSet("trace")
	protocolFlag := flags.String("protocol", "ctap2", "Protocol family: ctap1 or ctap2")
	commandFlag := flags.String("command", "", "Command byte in decimal or hex")
	payloadFlag := flags.String("payload", "", "Hex or base64 payload")
	if err := flags.Parse(args); err != nil {
		return err
	}
	commandCtx, cancel := withTimeout(ctx, common.timeout)
	defer cancel()

	family, err := parseProtocol(*protocolFlag)
	if err != nil {
		return err
	}
	command, err := parseCommand(*commandFlag)
	if err != nil {
		return err
	}
	payload, err := decodeBinary(*payloadFlag)
	if err != nil {
		return err
	}

	recorder := client.NewTraceRecorder()
	candidate, closeClient, err := app.openClient(commandCtx, common, client.WithTrace(recorder))
	if err != nil {
		return err
	}
	defer closeClient()

	response, err := candidate.InvokeRaw(commandCtx, family, command, payload)
	if err != nil {
		return err
	}
	result := struct {
		Response []byte              `json:"response"`
		Events   []client.TraceEvent `json:"events"`
	}{Response: response, Events: recorder.Events()}
	return writeValue(stdout, common.format, result, func(writer io.Writer) error {
		for _, event := range result.Events {
			if _, err := fmt.Fprintf(writer, "%s %x\n", event.Direction, event.Payload); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(writer, "response %x\n", result.Response)
		return err
	})
}

func newFlagSet(name string) (*flag.FlagSet, *commonFlags) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := &commonFlags{}
	flags.StringVar(&common.deviceID, "device-id", "", "Select a specific device")
	flags.DurationVar(&common.timeout, "timeout", 30*time.Second, "Command timeout")
	flags.StringVar(&common.format, "format", "human", "Output format: human, json, raw")
	flags.BoolVar(&common.verbose, "verbose", false, "Enable verbose output")
	flags.BoolVar(&common.debug, "debug", false, "Enable debug output")
	flags.BoolVar(&common.noInteractive, "no-interactive", false, "Disable interactive prompts")
	return flags, common
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func (app *application) openClient(ctx context.Context, common *commonFlags, options ...client.Option) (client.Client, func(), error) {
	if common.deviceID == "" {
		return nil, nil, client.ErrDeviceIDRequired
	}
	allOptions := append([]client.Option{client.WithDefaultRawInvokers()}, options...)
	candidate, err := app.locator.Open(ctx, common.deviceID, allOptions...)
	if err != nil {
		return nil, nil, err
	}
	return candidate, func() { _ = candidate.Close() }, nil
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

func preferredProtocol(caps *client.DeviceCapabilities) client.ProtocolFamily {
	family, ok := caps.PreferredProtocol()
	if !ok {
		return ""
	}
	return family
}

func classifyError(err error) int {
	var deviceErr *client.DeviceNotFoundError
	switch {
	case errors.As(err, &deviceErr), errors.Is(err, client.ErrDeviceIDRequired):
		return exitDeviceError
	case errors.Is(err, context.DeadlineExceeded):
		return exitTimeout
	case strings.Contains(strings.ToLower(err.Error()), "ctap"):
		return exitProtocol
	default:
		return exitGeneralError
	}
}

func writeRootUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "Usage: fido-go <command> [options]")
	_, _ = fmt.Fprintln(writer, "")
	_, _ = fmt.Fprintln(writer, "Commands:")
	_, _ = fmt.Fprintln(writer, "  list          List discovered authenticators")
	_, _ = fmt.Fprintln(writer, "  info          Show capabilities for one device")
	_, _ = fmt.Fprintln(writer, "  raw           Send a raw CTAP command")
	_, _ = fmt.Fprintln(writer, "  trace         Send a raw CTAP command with payload tracing")
	_, _ = fmt.Fprintln(writer, "  register      Run a basic registration flow")
	_, _ = fmt.Fprintln(writer, "  authenticate  Run a basic authentication flow")
	_, _ = fmt.Fprintln(writer, "  reset         Reset a CTAP2 authenticator")
	_, _ = fmt.Fprintln(writer, "  version       Print CLI version")
}
