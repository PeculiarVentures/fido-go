//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type identicalEpoch struct {
	owner                                                                     *identicalCollector
	endpoint                                                                  Endpoint
	conn                                                                      Conn
	cid                                                                       uint32
	role                                                                      string
	ordinal                                                                   int
	policy                                                                    *hotplugClosePolicy
	initialized, pingVerified, readObserved, removed, staleRejected           bool
	reuseRejected                                                             bool
	closeSuccess, qualified, closed, coreDone, leaseReleased                  bool
	realProbe, sameProbe, writerExited, writerJoined, deviceClosed, synthetic bool
	nativeAttributed                                                          bool
	closeFailure                                                              error
	hadQualifiedCloseError                                                    bool
}

func (epoch *identicalEpoch) prefix() string {
	if epoch.role == "" {
		return fmt.Sprintf("initial_epoch_%d_", epoch.ordinal)
	}
	return fmt.Sprintf("role_%s_epoch_%d_", epoch.role, epoch.ordinal)
}
func (epoch *identicalEpoch) enroll(role string, ordinal int) {
	epoch.role = role
	epoch.ordinal = ordinal
	epoch.policy.prefix = epoch.prefix()
}

func (collector *identicalCollector) openEpoch(ctx context.Context, endpoint Endpoint, role string, ordinal int) (*identicalEpoch, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	epoch := &identicalEpoch{owner: collector, endpoint: endpoint, role: role, ordinal: ordinal}
	epoch.policy = &hotplugClosePolicy{scope: collector.scope, prefix: epoch.prefix()}
	conn, err := collector.backend.Open(bounded, endpoint)
	if err != nil {
		return nil, err
	}
	epoch.conn = conn
	collector.epochs = append(collector.epochs, epoch)
	collector.scope.Defer(epoch.cleanup)
	if conn == nil {
		return nil, ErrIO
	}
	if conn.Layout().Input.Size != 64 || conn.Layout().Output.Size != 64 {
		return nil, diagnostics.InconclusiveReason("identical-key endpoint is outside the qualified CTAPHID layout")
	}
	if err := epoch.policy.attach(conn); err != nil {
		return nil, err
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	response, err := collector.message(bounded, epoch, 0xffffffff, 0x86, nonce)
	if err != nil {
		return nil, err
	}
	if len(response) < 17 || !bytes.Equal(response[:8], nonce) {
		return nil, errors.New("identical-key INIT did not echo its fresh nonce")
	}
	epoch.cid = binary.BigEndian.Uint32(response[8:12])
	if epoch.cid == 0 || epoch.cid == 0xffffffff {
		return nil, errors.New("identical-key INIT returned an invalid CID")
	}
	epoch.initialized = true
	if err := collector.ping(bounded, epoch); err != nil {
		return nil, err
	}
	return epoch, nil
}

func (collector *identicalCollector) message(ctx context.Context, epoch *identicalEpoch, cid uint32, command byte, payload []byte) ([]byte, error) {
	result, err := diagnosticHIDExchange(ctx, epoch.conn, cid, command, payload, nil)
	collector.confirmedWrites += uint64(result.FramesWritten)
	if err != nil {
		return nil, err
	}
	if result.FramesWritten != 1 || result.FramesRead != 1 || result.WriteResult.Outcome != OutcomeCompleted {
		return nil, errors.New("identical-key control message lacks exactly one completed report each way")
	}
	return result.Response, nil
}

func (collector *identicalCollector) ping(ctx context.Context, epoch *identicalEpoch) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	payload := make([]byte, 24)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	response, err := collector.message(bounded, epoch, epoch.cid, 0x81, payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(response, payload) {
		return errors.New("identical-key PING did not echo its distinct fresh payload")
	}
	epoch.pingVerified = true
	return nil
}

func (epoch *identicalEpoch) close(ctx context.Context) error {
	if epoch.conn == nil {
		return nil
	}
	// Both calls wait on the same supervisor cleanup. The first retains the SDK
	// outcome; only the existing evidence-qualified removal policy may normalize it.
	rawErr := epoch.conn.Close(ctx)
	policyErr := epoch.policy.close(ctx, epoch.conn)
	proof := hotplugCloseProof{}
	if epoch.policy.probe != nil {
		proof = epoch.policy.probe.proof()
	}
	epoch.realProbe, epoch.sameProbe = proof.RealProbe, proof.SameProbe && epoch.policy.conn == epoch.conn
	epoch.writerExited, epoch.writerJoined, epoch.deviceClosed = proof.WriterExited, proof.WriterJoined, proof.DeviceClosed
	epoch.synthetic = epoch.policy.probe != nil && !proof.RealProbe
	if raw, ok := epoch.conn.(*connection); ok {
		select {
		case <-raw.done:
			epoch.coreDone = true
		default:
		}
		shared.mu.Lock()
		epoch.leaseReleased = !shared.endpoints[raw.lease]
		shared.mu.Unlock()
	}
	nativeAvailable := platformDiagnosticCapabilities()["darwin-cgo"]
	epoch.closed = epoch.coreDone && epoch.leaseReleased && (!nativeAvailable || epoch.realProbe && epoch.sameProbe && proof.WriterExited && proof.WriterJoined && proof.DeviceClosed)
	// Qualify the original SDK error itself. A later successful wait cannot
	// turn an earlier deadline, permission failure, or unrelated I/O into the
	// narrowly reviewed post-removal diagnostic.
	qualification := proof
	qualification.AbsenceComplete = epoch.policy.absenceComplete
	qualification.RemovalObserved = epoch.policy.removalObserved
	qualification.SameProbe = epoch.sameProbe
	qualification.CoreDone = epoch.coreDone
	qualification.LeaseReleased = epoch.leaseReleased
	if rawErr != nil {
		if qualifiesHotplugCloseDiagnostic(rawErr, qualification) {
			epoch.hadQualifiedCloseError = true
		} else if epoch.closeFailure == nil {
			epoch.closeFailure = rawErr
		}
	}
	if policyErr != nil && epoch.closeFailure == nil {
		epoch.closeFailure = policyErr
	}
	epoch.closeSuccess = epoch.closeFailure == nil && !epoch.hadQualifiedCloseError
	epoch.qualified = epoch.closeFailure == nil && epoch.hadQualifiedCloseError
	if rawErr != nil && !epoch.nativeAttributed {
		var native *NativeError
		if errors.As(rawErr, &native) {
			epoch.owner.scope.Native(diagnostics.NativeError{Operation: epoch.prefix() + "Close", Domain: native.Domain, Code: native.Code})
			epoch.nativeAttributed = true
		}
	}
	epoch.record()
	if epoch.closeFailure != nil {
		return epoch.closeFailure
	}
	if !epoch.closed {
		return errors.New("identical-key epoch lacks completed native and core cleanup evidence")
	}
	return nil
}

func (epoch *identicalEpoch) cleanup(ctx context.Context) error {
	err := epoch.close(ctx)
	if epoch.policy.probe != nil {
		err = errors.Join(err, epoch.policy.probe.close())
	}
	return diagnosticSafeError(epoch.owner.scope, err)
}

func (epoch *identicalEpoch) record() {
	s, p := epoch.owner.scope, epoch.prefix()
	facts := map[string]bool{
		"initialized": epoch.initialized, "fresh_init_verified": epoch.initialized, "ping_echo_verified": epoch.pingVerified, "closed": epoch.closed, "core_cleanup_done": epoch.coreDone, "endpoint_lease_released": epoch.leaseReleased, "teardown_complete": epoch.closed,
		"synthetic_call": epoch.synthetic, "native_probe_available": platformDiagnosticCapabilities()["darwin-cgo"], "real_probe": epoch.realProbe, "same_probe": epoch.sameProbe, "writer_exited": epoch.writerExited, "writer_joined": epoch.writerJoined, "device_closed": epoch.deviceClosed,
		"native_close_success": epoch.closeSuccess, "expected_post_removal_close_diagnostic": epoch.qualified, "old_read_observed": epoch.readObserved, "old_read_admitted": false, "absence_complete": epoch.removed, "native_removal_error": epoch.readObserved, "old_connection_rejected": epoch.reuseRejected, "stale_exact_open_rejected": epoch.staleRejected,
	}
	for name, value := range facts {
		s.Fact(p+name, value)
	}
	count := uint64(0)
	if !epoch.closeSuccess {
		count = 1
	}
	s.Counter(p+"native_close_error_count", count)
	stale := uint64(0)
	if epoch.staleRejected {
		stale = 1
	}
	s.Counter(p+"stale_open_attempts", stale)
	s.Counter(p+"stale_open_rejections", stale)
}
