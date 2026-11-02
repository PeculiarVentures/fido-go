//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func TestHIDDiagnosticsHardware(t *testing.T) {
	if os.Getenv("FIDO_HID_DIAGNOSTICS") != "1" {
		t.Skip("set FIDO_HID_DIAGNOSTICS=1 for read-only hardware diagnostics")
	}
	opts := hidDiagnosticsOptions{Hardware: true, StrictIOKit: os.Getenv("FIDO_HID_DIAGNOSTICS_STRICT") == "1"}
	if ids := os.Getenv("FIDO_HID_DIAGNOSTICS_ENDPOINTS"); ids != "" {
		for _, id := range strings.Split(ids, ",") {
			if id == "" {
				t.Fatal("empty endpoint selector")
			}
			opts.EndpointIDs = append(opts.EndpointIDs, EndpointID(id))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report, err := runHIDDiagnostics(ctx, opts)
	if reportErr := writeDiagnosticReport(os.Getenv("FIDO_HID_DIAGNOSTICS_REPORT"), report); reportErr != nil {
		t.Fatal(reportErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnosticScenarios(t, report, expectedDeterministicDiagnosticIDs())
	assertNativeDiagnosticEvidence(t, report)
	found := map[string]diagnostics.Result{}
	for _, r := range report.Results {
		found[r.ScenarioID] = r
	}
	normal, ok := found["hardware.sigurg-ping"]
	if !ok || normal.Status != diagnostics.Pass || !normal.Cleanup.Complete {
		t.Fatalf("hardware pending-before-call result missing or incomplete: %+v", normal)
	}
	keys := normal.Counters["keys_selected"]
	if keys == 0 || normal.Counters["keys_completed"] != keys || len(opts.EndpointIDs) > 0 && keys != uint64(len(opts.EndpointIDs)) {
		t.Fatalf("hardware coverage selected=%d completed=%d", keys, normal.Counters["keys_completed"])
	}
	for _, fact := range []string{"all_ping_echoes_verified", "all_native_submissions_completed", "all_masks_restored", "all_signals_pending_before_real_call"} {
		if !normal.Facts[fact] {
			t.Errorf("hardware missing evidence %s", fact)
		}
	}
	for i := uint64(1); i <= keys; i++ {
		prefix := fmt.Sprintf("key_%d_", i)
		for _, name := range []string{"ping_echo_verified", "native_submission_completed", "mask_restored", "pending_before_real_call", "writer_joined"} {
			if !normal.Facts[prefix+name] {
				t.Errorf("key %d missing evidence %s", i, name)
			}
		}
		if normal.Facts[prefix+"synthetic_call"] || normal.Facts[prefix+"native_entry_confirmed"] || normal.Counters[prefix+"writer_generation"] == 0 || normal.Counters[prefix+"writer_generation"] != normal.Counters[prefix+"kill_generation"] {
			t.Errorf("key %d native evidence mismatched", i)
		}
	}
	strict, ok := found["hardware.strict-iokit-entry"]
	if !ok {
		t.Fatal("strict scenario missing")
	}
	if opts.StrictIOKit {
		switch strict.Status {
		case diagnostics.Pass:
			if !strict.Cleanup.Complete || !strict.Facts["all_native_entries_confirmed"] || strict.Counters["keys_selected"] != keys || strict.Counters["keys_completed"] != keys {
				t.Fatalf("strict entry evidence incomplete: %+v", strict)
			}
			for i := uint64(1); i <= keys; i++ {
				prefix := fmt.Sprintf("key_%d_", i)
				for _, name := range []string{"native_entry_confirmed", "entry_sigurg_blocked", "entry_pending_sigurg", "ping_echo_verified", "native_submission_completed", "mask_restored", "writer_joined"} {
					if !strict.Facts[prefix+name] {
						t.Errorf("strict key %d missing evidence %s", i, name)
					}
				}
				generation := strict.Counters[prefix+"writer_generation"]
				if generation == 0 || generation != strict.Counters[prefix+"kill_generation"] || generation != strict.Counters[prefix+"entry_generation"] || strict.Facts[prefix+"synthetic_call"] {
					t.Errorf("strict key %d generation/evidence mismatch", i)
				}
			}

		case diagnostics.Inconclusive, diagnostics.Skip:
			if strict.Facts["all_native_entries_confirmed"] {
				t.Fatal("unconfirmed entry incorrectly recorded")
			}
			t.Skipf("strict IOKit-entry evidence unavailable: %s", strict.Reason)
		default:
			t.Fatalf("strict entry failed: %+v", strict)
		}
	} else if strict.Status != diagnostics.Skip {
		t.Fatalf("unrequested strict scenario status=%s", strict.Status)
	}
	t.Logf("read-only hardware diagnostics passed for %d selected keys", keys)
}
