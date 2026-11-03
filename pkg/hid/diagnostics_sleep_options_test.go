//go:build hid_diagnostics && integration

package hid

import "testing"

func TestDiagnosticInteractiveModesAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name, unplug, sleep   string
		wantUnplug, wantSleep bool
	}{{"off", "", "", false, false}, {"sleep only", "", "1", false, true}, {"unplug only", "1", "", true, false}, {"both", "1", "1", true, true}, {"invalid values", "yes", "true", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				switch k {
				case "FIDO_HID_DIAGNOSTICS_UNPLUG":
					return tc.unplug
				case "FIDO_HID_DIAGNOSTICS_SLEEP":
					return tc.sleep
				}
				return ""
			}
			u, s := diagnosticInteractiveModes(getenv)
			if u != tc.wantUnplug || s != tc.wantSleep {
				t.Fatalf("unplug=%v sleep=%v", u, s)
			}
		})
	}
}

func TestDiagnosticScenarioOptInsDoNotAuthorizeEachOther(t *testing.T) {
	for _, tc := range []struct {
		name          string
		opts          hidDiagnosticsOptions
		unplug, sleep bool
	}{{"none", hidDiagnosticsOptions{}, false, false}, {"sleep", hidDiagnosticsOptions{InteractiveSleep: true}, false, true}, {"unplug", hidDiagnosticsOptions{InteractiveUnplug: true}, true, false}, {"both", hidDiagnosticsOptions{InteractiveSleep: true, InteractiveUnplug: true}, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if diagnosticInteractiveRequested("hardware.unplug-replug", tc.opts) != tc.unplug || diagnosticInteractiveRequested("hardware.sleep-wake-idle", tc.opts) != tc.sleep || diagnosticInteractiveRequested("hardware.sleep-wake-exchange", tc.opts) != tc.sleep {
				t.Fatal("interactive action authorized by the wrong opt-in")
			}
		})
	}
}
