package fidoctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

const reconnectPollInterval = 500 * time.Millisecond

// Service exposes the CLI business operations over the public SDK facade.
type Service interface {
	ListDevices(ctx context.Context) ([]client.Device, error)
	Info(ctx context.Context, deviceID string) (*InfoResult, error)
	Raw(ctx context.Context, request RawRequest) (*RawResult, error)
	Trace(ctx context.Context, request RawRequest) (*TraceResult, error)
	PINRetries(ctx context.Context, deviceID string) (*PINRetriesResult, error)
	SetPIN(ctx context.Context, deviceID string, newPIN string) error
	ChangePIN(ctx context.Context, deviceID string, currentPIN string, newPIN string) error
	Register(ctx context.Context, deviceID string, request client.RegisterRequest) (*client.RegistrationResult, error)
	Authenticate(ctx context.Context, deviceID string, request client.AuthenticateRequest) (*client.AssertionResult, error)
	Reset(ctx context.Context, deviceID string) error
	ListCredentials(ctx context.Context, deviceID string, pin string) (*CredentialListResult, error)
}

// App implements the fidoctl service layer.
type App struct {
	locator     client.Locator
	interactive bool
	status      io.Writer
}

// InfoResult contains device metadata and probed capabilities.
type InfoResult struct {
	Device       client.Device              `json:"device"`
	Capabilities *client.DeviceCapabilities `json:"capabilities"`
	PINRetries   *client.PINRetries         `json:"pinRetries,omitempty"`
}

// RawRequest configures a raw or traced invocation.
type RawRequest struct {
	DeviceID string
	Protocol client.ProtocolFamily
	Command  byte
	Payload  []byte
}

// RawResult contains a raw exchange result.
type RawResult struct {
	Protocol client.ProtocolFamily `json:"protocol"`
	Command  byte                  `json:"command"`
	Response []byte                `json:"response"`
}

// TraceResult contains a traced raw exchange result.
type TraceResult struct {
	Response []byte              `json:"response"`
	Events   []client.TraceEvent `json:"events"`
}

// CredentialListResult includes the selected device and its discoverable credentials.
type CredentialListResult struct {
	Device      client.Device                `json:"device"`
	Credentials *client.CredentialListResult `json:"credentials"`
}

// PINRetriesResult includes the selected device and its retry counters.
type PINRetriesResult struct {
	Device     client.Device      `json:"device"`
	PINRetries *client.PINRetries `json:"pinRetries"`
}

// New constructs the fidoctl business service.
func New(locator client.Locator) *App {
	return &App{locator: locator, interactive: true}
}

// NewDefault constructs the default local fidoctl service.
func NewDefault() (*App, error) {
	locator, err := client.NewDefaultLocator()
	if err != nil {
		return nil, err
	}
	return New(locator), nil
}

// ConfigureInteraction controls whether reconnect recovery is allowed and where status lines are written.
func (app *App) ConfigureInteraction(interactive bool, status io.Writer) {
	app.interactive = interactive
	app.status = status
}

// ListDevices enumerates visible authenticators.
func (app *App) ListDevices(ctx context.Context) ([]client.Device, error) {
	return app.locator.List(ctx)
}

// Info reads capabilities for the selected device.
func (app *App) Info(ctx context.Context, deviceID string) (*InfoResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*InfoResult, error) {
		caps, err := candidate.GetCapabilities(ctx)
		if err != nil {
			return nil, err
		}
		result := &InfoResult{Device: candidate.Device(), Capabilities: caps}
		if caps.HasCTAP2() && caps.CTAP2.Options["clientPin"] {
			retries, err := candidate.GetPINRetries(ctx)
			if err != nil {
				return nil, err
			}
			result.PINRetries = retries
		}
		return result, nil
	})
}

// Raw performs one raw protocol exchange.
func (app *App) Raw(ctx context.Context, request RawRequest) (*RawResult, error) {
	return withClient(app, ctx, request.DeviceID, nil, func(ctx context.Context, candidate client.Client) (*RawResult, error) {
		response, err := candidate.InvokeRaw(ctx, request.Protocol, request.Command, request.Payload)
		if err != nil {
			return nil, err
		}
		return &RawResult{Protocol: request.Protocol, Command: request.Command, Response: response}, nil
	})
}

// Trace performs one raw protocol exchange with trace collection enabled.
func (app *App) Trace(ctx context.Context, request RawRequest) (*TraceResult, error) {
	recorder := client.NewTraceRecorder()
	return withClient(app, ctx, request.DeviceID, []client.Option{client.WithTrace(recorder)}, func(ctx context.Context, candidate client.Client) (*TraceResult, error) {
		response, err := candidate.InvokeRaw(ctx, request.Protocol, request.Command, request.Payload)
		if err != nil {
			return nil, err
		}
		return &TraceResult{Response: response, Events: recorder.Events()}, nil
	})
}

// PINRetries reads the remaining PIN retry counters for the selected device.
func (app *App) PINRetries(ctx context.Context, deviceID string) (*PINRetriesResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*PINRetriesResult, error) {
		retries, err := candidate.GetPINRetries(ctx)
		if err != nil {
			return nil, err
		}
		return &PINRetriesResult{Device: candidate.Device(), PINRetries: retries}, nil
	})
}

// SetPIN configures a new authenticator PIN for the selected device.
func (app *App) SetPIN(ctx context.Context, deviceID string, newPIN string) error {
	_, previous, err := runWithClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (struct{}, error) {
		return struct{}{}, candidate.SetPIN(ctx, newPIN)
	})
	if err != nil {
		return err
	}
	app.waitForPostMutationReconnect(ctx, deviceID, previous, "PIN setup")
	return nil
}

// ChangePIN changes the authenticator PIN for the selected device.
func (app *App) ChangePIN(ctx context.Context, deviceID string, currentPIN string, newPIN string) error {
	_, previous, err := runWithClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (struct{}, error) {
		return struct{}{}, candidate.ChangePIN(ctx, currentPIN, newPIN)
	})
	if err != nil {
		return err
	}
	app.waitForPostMutationReconnect(ctx, deviceID, previous, "PIN change")
	return nil
}

// Register performs a credential-creation flow.
func (app *App) Register(ctx context.Context, deviceID string, request client.RegisterRequest) (*client.RegistrationResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*client.RegistrationResult, error) {
		return candidate.Register(ctx, request)
	})
}

// Authenticate performs an assertion flow.
func (app *App) Authenticate(ctx context.Context, deviceID string, request client.AuthenticateRequest) (*client.AssertionResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*client.AssertionResult, error) {
		return candidate.Authenticate(ctx, request)
	})
}

// Reset resets the selected authenticator.
func (app *App) Reset(ctx context.Context, deviceID string) error {
	_, err := withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (struct{}, error) {
		return struct{}{}, candidate.Reset(ctx)
	})
	return err
}

// ListCredentials enumerates discoverable credentials on the selected authenticator.
func (app *App) ListCredentials(ctx context.Context, deviceID string, pin string) (*CredentialListResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*CredentialListResult, error) {
		credentials, err := candidate.ListCredentials(ctx, pin)
		if err != nil {
			return nil, err
		}
		return &CredentialListResult{Device: candidate.Device(), Credentials: credentials}, nil
	})
}

func (app *App) openClient(ctx context.Context, deviceID string, options ...client.Option) (client.Client, func(), error) {
	allOptions := append([]client.Option{client.WithDefaultRawInvokers()}, options...)
	candidate, err := app.locator.Open(ctx, deviceID, allOptions...)
	if err != nil {
		return nil, nil, err
	}
	return candidate, func() { _ = candidate.Close() }, nil
}

func (app *App) waitForReconnect(ctx context.Context, deviceID string, previous *client.Device) error {
	ticker := time.NewTicker(reconnectPollInterval)
	defer ticker.Stop()
	for {
		if reconnectTargetAvailable(app.listDevices(ctx), deviceID, previous) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for authenticator reconnect: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (app *App) listDevices(ctx context.Context) []client.Device {
	devices, err := app.locator.List(ctx)
	if err != nil {
		return nil
	}
	return devices
}

func (app *App) shouldWaitForReconnect(err error) bool {
	if !app.interactive || err == nil {
		return false
	}
	var deviceErr *client.DeviceNotFoundError
	var transportErr *transport.Error
	if errors.As(err, &deviceErr) {
		return true
	}
	if !errors.As(err, &transportErr) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "hid") || strings.Contains(message, "iokit/common") || strings.Contains(message, "general error") || strings.Contains(message, "device was not found")
}

func (app *App) writeStatus(format string, args ...any) {
	if app.status == nil {
		return
	}
	_, _ = fmt.Fprintf(app.status, format+"\n", args...)
}

func (app *App) waitForPostMutationReconnect(ctx context.Context, deviceID string, previous *client.Device, operation string) {
	if !app.interactive || previous == nil {
		return
	}
	if reconnectTargetAvailable(app.listDevices(ctx), deviceID, previous) {
		return
	}
	app.writeStatus("Waiting for authenticator to reconnect after %s.", operation)
	if err := app.waitForReconnect(ctx, deviceID, previous); err == nil {
		app.writeStatus("Authenticator detected again.")
	}
}

func reconnectTargetAvailable(devices []client.Device, deviceID string, previous *client.Device) bool {
	if len(devices) == 0 {
		return false
	}
	if previous != nil {
		for _, device := range devices {
			if samePhysicalDevice(device, *previous) {
				return true
			}
		}
	}
	if deviceID == "" {
		return true
	}
	for _, device := range devices {
		if device.ID == deviceID {
			return true
		}
	}
	return false
}

func samePhysicalDevice(left client.Device, right client.Device) bool {
	if left.SerialNumber != "" && right.SerialNumber != "" {
		return left.Transport == right.Transport && left.SerialNumber == right.SerialNumber && left.VendorID == right.VendorID && left.ProductID == right.ProductID
	}
	return left.Transport == right.Transport && left.VendorID == right.VendorID && left.ProductID == right.ProductID && left.Product == right.Product && left.Manufacturer == right.Manufacturer
}

func withClient[T any](app *App, ctx context.Context, deviceID string, options []client.Option, operation func(context.Context, client.Client) (T, error)) (T, error) {
	result, previous, err := runWithClient(app, ctx, deviceID, options, operation)
	if err == nil || !app.shouldWaitForReconnect(err) {
		return result, err
	}

	app.writeStatus("Authenticator connection was lost. Reconnect the device to continue; waiting until the command timeout expires.")
	if waitErr := app.waitForReconnect(ctx, deviceID, previous); waitErr != nil {
		var zero T
		return zero, waitErr
	}
	app.writeStatus("Authenticator detected again. Retrying the command.")
	retried, _, retryErr := runWithClient(app, ctx, deviceID, options, operation)
	return retried, retryErr
}

func runWithClient[T any](app *App, ctx context.Context, deviceID string, options []client.Option, operation func(context.Context, client.Client) (T, error)) (T, *client.Device, error) {
	var zero T
	candidate, closeClient, err := app.openClient(ctx, deviceID, options...)
	if err != nil {
		return zero, nil, err
	}
	defer closeClient()
	device := candidate.Device()
	result, err := operation(ctx, candidate)
	if err != nil {
		return zero, &device, err
	}
	return result, &device, nil
}
