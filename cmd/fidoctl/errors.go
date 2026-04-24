package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

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

type commandErrorEnvelope struct {
	Error commandErrorPayload `json:"error"`
}

type commandErrorPayload struct {
	Message  string `json:"message"`
	ExitCode int    `json:"exitCode"`
	Kind     string `json:"kind"`
}

func writeCommandError(writer io.Writer, format string, err error) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(commandErrorEnvelope{
			Error: commandErrorPayload{
				Message:  err.Error(),
				ExitCode: classifyError(err),
				Kind:     errorKind(classifyError(err)),
			},
		})
	}
	_, writeErr := fmt.Fprintf(writer, "Error: %v\n", err)
	return writeErr
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
	case errors.Is(err, client.ErrPINRequired), errors.Is(err, client.ErrNewPINRequired):
		return exitUsageError
	case errors.Is(err, errResetConfirmationRequired):
		return exitUsageError
	default:
		return exitGeneralError
	}
}

func errorKind(exitCode int) string {
	switch exitCode {
	case exitUsageError:
		return "usage"
	case exitDeviceError:
		return "device"
	case exitTimeout:
		return "timeout"
	case exitProtocol:
		return "protocol"
	default:
		return "general"
	}
}
