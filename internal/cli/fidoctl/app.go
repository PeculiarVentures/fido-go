package fidoctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

const reconnectPollInterval = 500 * time.Millisecond
const ctap2StatusNotAllowed = 0x30

// Service exposes the CLI business operations over the public SDK facade.
type Service interface {
	ListDevices(ctx context.Context) ([]client.Device, error)
	Info(ctx context.Context, deviceID string) (*InfoResult, error)
	Raw(ctx context.Context, request RawRequest) (*RawResult, error)
	Trace(ctx context.Context, request RawRequest) (*TraceResult, error)
	PINRetries(ctx context.Context, deviceID string) (*PINRetriesResult, error)
	SetPIN(ctx context.Context, deviceID string, newPIN client.Secret) error
	ChangePIN(ctx context.Context, deviceID string, currentPIN client.Secret, newPIN client.Secret) error
	Register(ctx context.Context, deviceID string, request client.RegistrationRequest) (*client.RegistrationResult, error)
	Authenticate(ctx context.Context, deviceID string, request client.AuthenticationRequest) (*client.AuthenticationResult, error)
	Reset(ctx context.Context, deviceID string) error
	ListCredentials(ctx context.Context, deviceID string, pin client.Secret) (*CredentialListResult, error)
}

// App implements the fidoctl service layer.
type App struct {
	locator     client.Locator
	interactive bool
	status      io.Writer
}

// InfoResult contains device metadata and probed capabilities.
type InfoResult struct {
	Device       client.Device        `json:"device"`
	Capabilities *client.Capabilities `json:"capabilities"`
	PINRetries   *client.PINRetries   `json:"pinRetries,omitempty"`
}

// RawRequest configures a raw or traced invocation.
type RawRequest struct {
	DeviceID    string
	Protocol    client.ProtocolFamily
	Command     byte
	Payload     []byte
	UnsafeTrace bool
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
		caps, err := candidate.Capabilities(ctx)
		if err != nil {
			return nil, err
		}
		result := &InfoResult{Device: candidate.Device(), Capabilities: caps}
		app.attachPINRetries(ctx, candidate, caps, result)
		return result, nil
	})
}

func (app *App) attachPINRetries(ctx context.Context, candidate client.Client, caps *client.Capabilities, result *InfoResult) {
	if caps == nil || !caps.HasCTAP2() || !caps.Verification.ClientPIN || result == nil {
		return
	}
	ctap2Candidate, err := candidate.CTAP2(ctx)
	if err != nil {
		app.writeStatus("warning: unable to read authenticator PIN status: %v", err)
		return
	}
	status, err := ctap2Candidate.PIN().Status(ctx)
	if err != nil {
		app.writeStatus("warning: unable to read authenticator PIN status: %v", err)
		return
	}
	if status.Configured {
		result.PINRetries = pinStatusToRetries(status)
	}
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
	return withClient(app, ctx, request.DeviceID, []client.Option{client.WithTrace(recorder, client.TraceOptions{RedactSecrets: !request.UnsafeTrace})}, func(ctx context.Context, candidate client.Client) (*TraceResult, error) {
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
		ctap2Candidate, err := candidate.CTAP2(ctx)
		if err != nil {
			return nil, err
		}
		status, err := ctap2Candidate.PIN().Status(ctx)
		if err != nil {
			return nil, err
		}
		return &PINRetriesResult{Device: candidate.Device(), PINRetries: pinStatusToRetries(status)}, nil
	})
}

// SetPIN configures a new authenticator PIN for the selected device.
func (app *App) SetPIN(ctx context.Context, deviceID string, newPIN client.Secret) error {
	_, previous, err := runWithClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (struct{}, error) {
		ctap2Candidate, err := candidate.CTAP2(ctx)
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, ctap2Candidate.PIN().Set(ctx, newPIN)
	})
	if err != nil {
		return err
	}
	app.waitForPostMutationReconnect(ctx, deviceID, previous, "PIN setup")
	return nil
}

// ChangePIN changes the authenticator PIN for the selected device.
func (app *App) ChangePIN(ctx context.Context, deviceID string, currentPIN client.Secret, newPIN client.Secret) error {
	_, previous, err := runWithClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (struct{}, error) {
		ctap2Candidate, err := candidate.CTAP2(ctx)
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, ctap2Candidate.PIN().Change(ctx, currentPIN, newPIN)
	})
	if err != nil {
		return err
	}
	app.waitForPostMutationReconnect(ctx, deviceID, previous, "PIN change")
	return nil
}

// Register performs a credential-creation flow.
func (app *App) Register(ctx context.Context, deviceID string, request client.RegistrationRequest) (*client.RegistrationResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*client.RegistrationResult, error) {
		return candidate.Register(ctx, request)
	})
}

// Authenticate performs an assertion flow.
func (app *App) Authenticate(ctx context.Context, deviceID string, request client.AuthenticationRequest) (*client.AuthenticationResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*client.AuthenticationResult, error) {
		return candidate.Authenticate(ctx, request)
	})
}

// Reset resets the selected authenticator.
func (app *App) Reset(ctx context.Context, deviceID string) error {
	operation := func(ctx context.Context, candidate client.Client) (struct{}, error) {
		ctap2Candidate, err := candidate.CTAP2(ctx)
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, ctap2Candidate.Reset(ctx)
	}
	_, previous, err := runWithClient(app, ctx, deviceID, nil, operation)
	if err == nil {
		return nil
	}
	switch {
	case app.shouldRetryResetAfterPowerCycle(err):
		if waitErr := app.waitForResetWindow(ctx, deviceID, previous); waitErr != nil {
			return waitErr
		}
	case app.shouldWaitForReconnect(err):
		app.writeStatus("Authenticator connection was lost. Reconnect the device to continue; waiting until the command timeout expires.")
		if waitErr := app.waitForReconnect(ctx, deviceID, previous); waitErr != nil {
			return waitErr
		}
		app.writeStatus("Authenticator detected again. Retrying the command.")
	default:
		return err
	}
	_, _, err = runWithClient(app, ctx, deviceID, nil, operation)
	return err
}

// ListCredentials enumerates discoverable credentials on the selected authenticator.
func (app *App) ListCredentials(ctx context.Context, deviceID string, pin client.Secret) (*CredentialListResult, error) {
	return withClient(app, ctx, deviceID, nil, func(ctx context.Context, candidate client.Client) (*CredentialListResult, error) {
		ctap2Candidate, err := candidate.CTAP2(ctx)
		if err != nil {
			return nil, err
		}
		credentials, err := ctap2Candidate.Credentials().List(ctx, client.UVAuthorization{PIN: pin, Method: client.VerificationMethodPIN})
		if err != nil {
			return nil, err
		}
		return &CredentialListResult{Device: candidate.Device(), Credentials: credentials}, nil
	})
}

func (app *App) openClient(ctx context.Context, deviceID string, options ...client.Option) (client.Client, func(), error) {
	allOptions := append([]client.Option{client.WithDefaultRawInvokers(), client.WithInteraction(app)}, options...)
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

func (app *App) waitForResetWindow(ctx context.Context, deviceID string, previous *client.Device) error {
	app.writeStatus("Authenticator reset was rejected because the reset window is closed. Reinsert or retap the authenticator, then touch it when prompted.")
	if previous == nil {
		return app.waitForReconnect(ctx, deviceID, previous)
	}

	removed := !reconnectTargetAvailable(app.listDevices(ctx), deviceID, previous)
	ticker := time.NewTicker(reconnectPollInterval)
	defer ticker.Stop()

	for !removed {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for authenticator removal before reset retry: %w", ctx.Err())
		case <-ticker.C:
			removed = !reconnectTargetAvailable(app.listDevices(ctx), deviceID, previous)
		}
	}

	app.writeStatus("Authenticator removed. Waiting for it to reconnect inside the reset window.")
	for {
		if reconnectTargetAvailable(app.listDevices(ctx), deviceID, previous) {
			app.writeStatus("Authenticator detected again. Retrying reset immediately.")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for authenticator reconnect before reset retry: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (app *App) listDevices(ctx context.Context) []client.Device {
	devices, err := app.locator.List(ctx)
	if err != nil && len(devices) == 0 {
		return nil
	}
	return devices
}

func (app *App) shouldWaitForReconnect(err error) bool {
	if !app.interactive || err == nil {
		return false
	}
	var deviceErr *client.DeviceNotFoundError
	if errors.As(err, &deviceErr) {
		return true
	}
	return errors.Is(err, transport.ErrDisconnected) || errors.Is(err, transport.ErrTemporary)
}

func (app *App) shouldRetryResetAfterPowerCycle(err error) bool {
	if !app.interactive || err == nil {
		return false
	}
	var ctapErr *ctap2.Error
	return errors.As(err, &ctapErr) && ctapErr.Code == ctap2StatusNotAllowed
}

func (app *App) writeStatus(format string, args ...any) {
	if app.status == nil {
		return
	}
	_, _ = fmt.Fprintf(app.status, format+"\n", args...)
}

// OnInteraction writes interaction diagnostics to the configured status stream.
func (app *App) OnInteraction(_ context.Context, event client.InteractionEvent) {
	if !app.interactive {
		return
	}
	message := event.Message
	if message == "" {
		switch event.Kind {
		case client.InteractionAwaitingUserPresence:
			message = "Touch or tap the authenticator to continue."
		case client.InteractionAwaitingUserVerification:
			message = "Complete authenticator verification to continue."
		case client.InteractionAwaitingPIN:
			message = "Authenticator PIN is required."
		case client.InteractionReinsertRequired:
			message = "Reinsert or retap the authenticator to continue."
		case client.InteractionProcessing:
			message = "Processing authenticator request."
		}
	}
	if message != "" {
		app.writeStatus(message)
	}
}

// RequestPIN satisfies the SDK interaction contract for CLI callers that provide PINs explicitly.
func (app *App) RequestPIN(_ context.Context, req client.PINRequest) (client.Secret, error) {
	if req.Message != "" {
		app.writeStatus(req.Message)
	}
	return nil, client.ErrPINRequired
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

func pinStatusToRetries(status *client.PINStatus) *client.PINRetries {
	if status == nil {
		return nil
	}
	return &client.PINRetries{
		PINRetries:      status.Retries,
		UVRetries:       status.UVRetries,
		PowerCycleState: status.PowerCycleNeeded,
	}
}
