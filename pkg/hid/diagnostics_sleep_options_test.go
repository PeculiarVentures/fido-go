//go:build hid_diagnostics && integration

package hid

import "testing"

func TestDiagnosticInteractiveModesAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name, unplug, sleep, identical       string
		wantUnplug, wantSleep, wantIdentical bool
	}{{"off", "", "", "", false, false, false}, {"sleep only", "", "1", "", false, true, false}, {"unplug only", "1", "", "", true, false, false}, {"identical only", "", "", "1", false, false, true}, {"all", "1", "1", "1", true, true, true}, {"invalid", "yes", "true", "yes", false, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				switch k {
				case "FIDO_HID_DIAGNOSTICS_UNPLUG":
					return tc.unplug
				case "FIDO_HID_DIAGNOSTICS_SLEEP":
					return tc.sleep
				case "FIDO_HID_DIAGNOSTICS_IDENTICAL":
					return tc.identical
				}
				return ""
			}
			u, s, i := diagnosticInteractiveModes(getenv)
			if u != tc.wantUnplug || s != tc.wantSleep || i != tc.wantIdentical {
				t.Fatalf("unplug=%v sleep=%v identical=%v", u, s, i)
			}
		})
	}
}
func TestDiagnosticScenarioOptInsDoNotAuthorizeEachOther(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		opts                     hidDiagnosticsOptions
		unplug, sleep, identical bool
	}{{"none", hidDiagnosticsOptions{}, false, false, false}, {"sleep", hidDiagnosticsOptions{InteractiveSleep: true}, false, true, false}, {"unplug", hidDiagnosticsOptions{InteractiveUnplug: true}, true, false, false}, {"identical", hidDiagnosticsOptions{InteractiveIdentical: true}, false, false, true}, {"all", hidDiagnosticsOptions{InteractiveSleep: true, InteractiveUnplug: true, InteractiveIdentical: true}, true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if diagnosticInteractiveRequested("hardware.unplug-replug", tc.opts) != tc.unplug || diagnosticInteractiveRequested("hardware.sleep-wake-idle", tc.opts) != tc.sleep || diagnosticInteractiveRequested("hardware.sleep-wake-exchange", tc.opts) != tc.sleep || diagnosticInteractiveRequested("hardware.identical-keys", tc.opts) != tc.identical {
				t.Fatal("interactive action authorized by wrong opt-in")
			}
		})
	}
}
