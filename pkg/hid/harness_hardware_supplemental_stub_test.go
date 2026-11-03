//go:build hid_diagnostics && integration && (!darwin || !cgo)

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func supplementalNativeWriteAvailable() bool { return false }
func diagnoseNativeWriteCancellation(context.Context, *diagnostics.Scope, Endpoint, int) error {
	return nil
}
