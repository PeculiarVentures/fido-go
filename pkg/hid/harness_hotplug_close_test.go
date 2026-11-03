//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// This exception belongs only to the physical removal scenario, never the SDK.
type hotplugCloseProof struct {
	AbsenceComplete, RemovalObserved, RealProbe, SameProbe bool
	WriterExited, WriterJoined, DeviceClosed               bool
	CoreDone, LeaseReleased                                bool
}

type hotplugCloseProbe interface {
	proof() hotplugCloseProof
	close() error
}

type hotplugClosePolicy struct {
	scope                            *diagnostics.Scope
	prefix                           string
	conn                             Conn
	probe                            hotplugCloseProbe
	absenceComplete, removalObserved bool
}

func (policy *hotplugClosePolicy) attach(conn Conn) error {
	probe, err := attachHotplugCloseProbe(conn)
	if err != nil {
		return err
	}
	policy.conn, policy.probe = conn, probe
	return nil
}

func (policy *hotplugClosePolicy) close(ctx context.Context, conn Conn) error {
	err := conn.Close(ctx)
	proof := hotplugCloseProof{AbsenceComplete: policy.absenceComplete, RemovalObserved: policy.removalObserved}
	if policy.probe != nil {
		native := policy.probe.proof()
		proof.RealProbe, proof.SameProbe = native.RealProbe, native.SameProbe && policy.conn == conn
		proof.WriterExited, proof.WriterJoined, proof.DeviceClosed = native.WriterExited, native.WriterJoined, native.DeviceClosed
	}
	if raw, ok := conn.(*connection); ok {
		select {
		case <-raw.done:
			proof.CoreDone = true
		default:
		}
		shared.mu.Lock()
		proof.LeaseReleased = !shared.endpoints[raw.lease]
		shared.mu.Unlock()
	}
	policy.scope.Fact(policy.prefix+"native_close_success", err == nil)
	policy.scope.Fact(policy.prefix+"core_cleanup_done", proof.CoreDone)
	policy.scope.Fact(policy.prefix+"endpoint_lease_released", proof.LeaseReleased)
	policy.scope.Fact(policy.prefix+"writer_exited", proof.WriterExited)
	policy.scope.Fact(policy.prefix+"writer_joined", proof.WriterJoined)
	policy.scope.Fact(policy.prefix+"device_closed", proof.DeviceClosed)
	policy.scope.Fact(policy.prefix+"teardown_complete", proof.CoreDone && proof.LeaseReleased &&
		(!proof.RealProbe || (proof.SameProbe && proof.WriterExited && proof.WriterJoined && proof.DeviceClosed)))
	if err == nil {
		return nil
	}
	// Preserve the actual native code even when independent evidence proves
	// teardown completed after removal. The SDK's Close result is unchanged.
	safe := diagnosticSafeError(policy.scope, err)
	if qualifiesHotplugCloseDiagnostic(err, proof) {
		policy.scope.Fact(policy.prefix+"expected_post_removal_close_diagnostic", true)
		return nil
	}
	return safe
}

func (policy *hotplugClosePolicy) cleanup(ctx context.Context, conn Conn) error {
	// Keep the same probe alive through repeated Close and qualification.
	if policy.probe != nil {
		defer policy.probe.close()
	}
	return policy.close(ctx, conn)
}

func qualifiesHotplugCloseDiagnostic(err error, proof hotplugCloseProof) bool {
	if err == nil || !proof.AbsenceComplete || !proof.RemovalObserved || !proof.RealProbe || !proof.SameProbe ||
		!proof.WriterExited || !proof.WriterJoined || !proof.DeviceClosed || !proof.CoreDone || !proof.LeaseReleased ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	closeOperation, nativeCode, invalid := false, false, false
	var walk func(error)
	walk = func(cause error) {
		if cause == nil {
			return
		}
		var domain string
		var code uint64
		recognized := false
		switch value := cause.(type) {
		case *Error:
			recognized = true
			if value.Op == "close" && value.Kind == ErrIO {
				closeOperation = true
			} else {
				invalid = true
			}
		case *driver.Error:
			recognized = true
			if value.Op == "close" && value.Kind == driver.KindIO {
				closeOperation = true
			} else {
				invalid = true
			}
			domain, code = value.Domain, value.Code
		case *NativeError:
			recognized = true
			domain, code = value.Domain, value.Code
		}
		if domain != "" {
			if domain == "iokit" && code == 0xe00002c2 {
				nativeCode = true
			} else {
				invalid = true
			}
		}
		if many, ok := cause.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				if child != nil {
					recognized = true
				}
				walk(child)
			}
		}
		if one, ok := cause.(interface{ Unwrap() error }); ok {
			child := one.Unwrap()
			if child != nil {
				recognized = true
			}
			walk(child)
		}
		if !recognized && cause != ErrIO {
			invalid = true
		}
	}
	walk(err)
	return closeOperation && nativeCode && !invalid
}
