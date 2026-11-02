//go:build darwin && cgo && hid_diagnostics

package darwin

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

func TestDiagnosticsNativeMaskAndPendingSIGURG(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "unblocked", true: "blocked"}[blocked], func(t *testing.T) {
			d, p, err := NewSynthetic(Config{InitialSIGURGBlocked: blocked, BlockUnrelatedSignal: true, InjectSIGURG: true})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			defer d.Close()
			result, err := d.Write(driver.Report{Data: make([]byte, 64)})
			s := p.Snapshot()
			if err != nil || result.Outcome != driver.OutcomeCompleted {
				t.Fatalf("write=%+v err=%v", result, err)
			}
			if !s.Synthetic || s.Generation == 0 || s.Writes != 1 || s.SetReportCalls != 1 || s.KillAttempts != 1 || s.KillError != 0 || s.KillGeneration != s.Generation || s.BeforeSIGURGBlocked != blocked || !s.BeforeUnrelatedBlocked || !s.CriticalSIGURGBlocked || !s.PendingSIGURG || !s.MaskRestored || s.AfterSIGURGBlocked != blocked || !s.AfterUnrelatedBlocked || s.EntryConfirmed || s.InitialMaskError != 0 || s.MaskQueryError != 0 {
				t.Fatalf("mask/signal evidence: %+v", s)
			}
		})
	}
}
func TestDiagnosticsNativeSetupFailureDoesNotSubmit(t *testing.T) {
	d, p, err := NewSynthetic(Config{SetupError: int(syscall.EPERM), BlockUnrelatedSignal: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	defer d.Close()
	result, err := d.Write(driver.Report{Data: make([]byte, 64)})
	s := p.Snapshot()
	var native *driver.Error
	if !errors.As(err, &native) || native.Domain != "pthread" || native.Code != uint64(syscall.EPERM) || result.Outcome != driver.OutcomeNotSubmitted || s.SetReportCalls != 0 || s.Submitted || s.SetupError != int(syscall.EPERM) || !s.MaskRestored {
		t.Fatalf("result=%+v err=%v evidence=%+v", result, err, s)
	}
}
func TestDiagnosticsNativeRestoreFailureRetiresWriterAndRetainsOutcomes(t *testing.T) {
	for _, ioCode := range []uint32{0, 0xe00002bc} {
		t.Run(map[bool]string{true: "native-success", false: "native-failure"}[ioCode == 0], func(t *testing.T) {
			d, p, err := NewSynthetic(Config{RestoreError: int(syscall.EPERM), NativeError: ioCode})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			closed := false
			defer func() {
				if !closed {
					_ = d.Close()
				}
			}()
			result, writeErr := d.Write(driver.Report{Data: make([]byte, 64)})
			if writeErr == nil {
				t.Fatal("missing restore error")
			}
			want := driver.OutcomeCompleted
			if ioCode != 0 {
				want = driver.OutcomeUnknown
			}
			if result.Outcome != want {
				t.Fatalf("outcome=%v want=%v", result.Outcome, want)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := p.Wait(ctx, PhaseWriterExited); err != nil {
				t.Fatal(err)
			}
			s := p.Snapshot()
			if s.RestoreError != int(syscall.EPERM) || s.NativeError != ioCode || s.SetReportCalls != 1 || !s.WriterExited {
				t.Fatalf("restore evidence: %+v", s)
			}
			second, secondErr := d.Write(driver.Report{Data: make([]byte, 64)})
			if secondErr == nil || second.Outcome != driver.OutcomeNotSubmitted {
				t.Fatalf("dead writer reused: %+v %v", second, secondErr)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			s, err = p.Wait(ctx, PhaseWriterJoined|PhaseDeviceClosed)
			if err != nil || !s.WriterJoined || !s.DeviceClosed || s.SetReportCalls != 1 {
				t.Fatalf("join evidence=%+v err=%v", s, err)
			}
			domains := map[string]bool{}
			var walk func(error)
			walk = func(e error) {
				if e == nil {
					return
				}
				if n, ok := e.(*driver.Error); ok {
					domains[n.Domain] = true
				}
				switch x := e.(type) {
				case interface{ Unwrap() []error }:
					for _, e := range x.Unwrap() {
						walk(e)
					}
				case interface{ Unwrap() error }:
					walk(x.Unwrap())
				}
			}
			walk(writeErr)
			if !domains["pthread"] || ioCode != 0 && !domains["iokit"] {
				t.Fatalf("lost native error domains: %v, %v", domains, writeErr)
			}
		})
	}
}
