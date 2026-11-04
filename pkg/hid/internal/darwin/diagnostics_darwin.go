//go:build darwin && cgo && hid_diagnostics

package darwin

/*
#cgo CFLAGS: -DHID_DIAGNOSTICS=1
#include "diagnostics_native.h"
#include <errno.h>
*/
import "C"

import (
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Config applies once to the next admitted write on an idle probe. NativeError
// substitutes a SetReport result only for synthetic devices. HoldNative pauses
// the native boundary until Release or Close; the public caller can cancel while
// the actual writer remains owned by the connection. SIGUSR1 is the unrelated
// signal whose initial membership is selected by BlockUnrelatedSignal.
type Config struct {
	InitialSIGURGBlocked bool
	BlockUnrelatedSignal bool
	InjectSIGURG         bool
	HoldNative           bool
	StrictEntry          bool
	SetupError           int
	RestoreError         int
	NativeError          uint32
}

// Phase identifies bounded native lifecycle evidence. PhaseNative is the
// synthetic call boundary or the protected pending-before-real-call boundary;
// it does not prove entry into actual IOKit. Only EntryConfirmed records the
// separate debugger-verified native-entry helper.
type Phase uint8

const (
	PhaseNative Phase = 1 << iota
	PhaseWriterExited
	PhaseWriterJoined
	PhaseDeviceClosed
)

// Snapshot is independent of connection lifetime and contains no report bytes,
// serials, native pointers, or reusable pthread identifiers. MaskRestored compares
// every valid signal membership, rather than opaque sigset_t padding bytes.
type Snapshot struct {
	Generation, Writes, SetReportCalls, KillAttempts, KillGeneration uint64
	EntryGeneration                                                  uint64
	Synthetic, Armed                                                 bool
	Phases                                                           Phase
	KillError, InitialMaskError, MaskQueryError                      int
	BeforeSIGURGBlocked, BeforeUnrelatedBlocked                      bool
	CriticalSIGURGBlocked, PendingSIGURG                             bool
	AfterSIGURGBlocked, AfterUnrelatedBlocked, MaskRestored          bool
	SetupError, RestoreError                                         int
	NativeError                                                      uint32
	Submitted, Completed                                             bool
	WriterExited, WriterJoined, DeviceClosed, EntryConfirmed         bool
	EntrySIGURGBlocked, EntryPendingSIGURG                           bool
	EntryMaskQueryError                                              int
}

// Probe owns a native reference independently of its attached device. Close
// releases barriers and that reference without waiting for a pending native
// write. The connection retains its own reference through actual cleanup.
type Probe struct {
	mu     sync.Mutex
	native *C.hid_diagnostic_probe
	last   Snapshot
}

// NewSynthetic starts the same production writer_main/protected_write pthread
// path with a controlled native substitute. It never opens a physical device.
// Its fixed Input/Output layout is 64 bytes, with Report IDs zero.
func NewSynthetic(config Config) (driver.Device, *Probe, error) {
	if err := validateConfig(config); err != nil {
		return nil, nil, err
	}
	probe, err := newProbe()
	if err != nil {
		return nil, nil, err
	}
	var nativeError C.int
	connection := C.hid_diagnostic_connect(probe.native, &nativeError)
	if connection == nil {
		_ = probe.Close()
		return nil, nil, pthreadError("diagnostic synthetic open", nativeError)
	}
	state := probe.Snapshot()
	d := &device{
		native: connection,
		endpoint: driver.Endpoint{
			ID:    fmt.Sprintf("diagnostic:%d", state.Generation),
			Bus:   driver.BusUSB,
			Usage: driver.Field[driver.Usage]{Known: true, Value: driver.Usage{Page: 0xf1d0, ID: 1}},
		},
		layout: driver.Layout{Input: driver.ReportSpec{Size: 64}, Output: driver.ReportSpec{Size: 64}},
	}
	if err = probe.Arm(config); err != nil {
		_ = d.Close()
		_ = probe.Close()
		return nil, nil, err
	}
	return d, probe, nil
}

// Attach installs an initially unarmed probe on an idle native device. Complete
// normal INIT first, then Arm before the specific hardware PING being measured.
// The caller must serialize Attach with driver operations and physical Close.
func Attach(nativeDevice driver.Device) (*Probe, error) {
	d, ok := nativeDevice.(*device)
	if !ok || d == nil || d.native == nil {
		return nil, failure("diagnostic attach", driver.KindInvalidArgument, "expected an open Darwin native device")
	}
	probe, err := newProbe()
	if err != nil {
		return nil, err
	}
	code := C.hid_diagnostic_attach(d.native, probe.native)
	if code != 0 {
		_ = probe.Close()
		return nil, pthreadError("diagnostic attach", code)
	}
	return probe, nil
}

func newProbe() (*Probe, error) {
	native := C.hid_diagnostic_probe_new()
	if native == nil {
		return nil, failure("diagnostic probe", driver.KindResourceLimit, "native probe allocation or 64-probe limit")
	}
	return &Probe{native: native}, nil
}

// Arm configures exactly one next write; an active, armed, exited, or closed
// probe cannot be rearmed. Each configuration is scoped to this probe.
func (p *Probe) Arm(config Config) error {
	if err := validateConfig(config); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return failure("diagnostic arm", driver.KindClosed, "probe closed")
	}
	var native C.hid_diagnostic_snapshot
	C.hid_diagnostic_snapshot_read(p.native, &native)
	if native.synthetic == 0 && config.NativeError != 0 {
		return failure("diagnostic arm", driver.KindInvalidArgument, "native result substitution requires a synthetic device")
	}
	code := C.hid_diagnostic_arm(p.native, nativeConfig(config))
	if code != 0 {
		return pthreadError("diagnostic arm", code)
	}
	return nil
}

// Snapshot copies the latest native evidence. After Probe.Close it returns the
// final snapshot captured while releasing the caller's native reference.
func (p *Probe) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked()
}

func (p *Probe) snapshotLocked() Snapshot {
	if p.native != nil {
		var s C.hid_diagnostic_snapshot
		C.hid_diagnostic_snapshot_read(p.native, &s)
		p.last = Snapshot{
			Generation: uint64(s.generation), Writes: uint64(s.writes), SetReportCalls: uint64(s.native_calls),
			KillAttempts: uint64(s.kill_attempts), KillGeneration: uint64(s.kill_generation), EntryGeneration: uint64(s.entry_generation),
			Synthetic: s.synthetic != 0, Armed: s.armed != 0, Phases: Phase(s.phases),
			KillError: int(s.kill_error), InitialMaskError: int(s.initial_mask_error), MaskQueryError: int(s.mask_query_error),
			BeforeSIGURGBlocked: s.before_urgent != 0, BeforeUnrelatedBlocked: s.before_unrelated != 0,
			CriticalSIGURGBlocked: s.critical_urgent != 0, PendingSIGURG: s.pending_urgent != 0,
			AfterSIGURGBlocked: s.after_urgent != 0, AfterUnrelatedBlocked: s.after_unrelated != 0, MaskRestored: s.mask_restored != 0,
			SetupError: int(s.setup_error), RestoreError: int(s.restore_error), NativeError: uint32(s.native_error),
			Submitted: s.submitted != 0, Completed: s.completed != 0,
			WriterExited: s.writer_exited != 0, WriterJoined: s.writer_joined != 0,
			DeviceClosed: s.device_closed != 0, EntryConfirmed: s.entry_confirmed != 0,
			EntrySIGURGBlocked: s.entry_urgent != 0, EntryPendingSIGURG: s.entry_pending != 0,
			EntryMaskQueryError: int(s.entry_mask_error),
		}
	}
	return p.last
}

// Wait observes a native phase without retaining an outstanding waiter after
// cancellation. Native condition waits are bounded to 20 ms per context check.
func (p *Probe) Wait(ctx context.Context, phase Phase) (Snapshot, error) {
	if ctx == nil || phase == 0 || phase & ^(PhaseNative|PhaseWriterExited|PhaseWriterJoined|PhaseDeviceClosed) != 0 {
		return Snapshot{}, failure("diagnostic wait", driver.KindInvalidArgument, "invalid context or phase")
	}
	for {
		if err := ctx.Err(); err != nil {
			return p.Snapshot(), err
		}
		p.mu.Lock()
		if p.native == nil {
			snapshot := p.last
			p.mu.Unlock()
			return snapshot, failure("diagnostic wait", driver.KindClosed, "probe closed")
		}
		code := C.hid_diagnostic_wait(p.native, C.int(phase), 20)
		snapshot := p.snapshotLocked()
		p.mu.Unlock()
		if code == 0 {
			return snapshot, nil
		}
		if code != C.ETIMEDOUT {
			return snapshot, pthreadError("diagnostic wait", code)
		}
	}
}

// Release idempotently opens the native barrier while keeping probe ownership.
func (p *Probe) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native != nil {
		C.hid_diagnostic_release_barrier(p.native)
	}
	return nil
}

// Close idempotently releases the barrier and the caller's native reference.
// A blocked native operation and its connection continue to own their reference.
func (p *Probe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native != nil {
		p.snapshotLocked()
		C.hid_diagnostic_probe_close(p.native)
		p.native = nil
	}
	return nil
}

func validateConfig(config Config) error {
	if config.SetupError < 0 || int64(config.SetupError) > math.MaxInt32 ||
		config.RestoreError < 0 || int64(config.RestoreError) > math.MaxInt32 {
		return failure("diagnostic config", driver.KindInvalidArgument, "fault codes must be nonnegative native integers")
	}
	return nil
}

func nativeConfig(config Config) C.hid_diagnostic_config {
	return C.hid_diagnostic_config{
		initial_urgent_blocked: cbool(config.InitialSIGURGBlocked), unrelated_blocked: cbool(config.BlockUnrelatedSignal),
		inject_urgent: cbool(config.InjectSIGURG), hold_native: cbool(config.HoldNative), strict_entry: cbool(config.StrictEntry),
		setup_error: C.int(config.SetupError), restore_error: C.int(config.RestoreError), native_error: C.uint32_t(config.NativeError),
	}
}

func cbool(value bool) C.int {
	if value {
		return 1
	}
	return 0
}
