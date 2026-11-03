//go:build hid_diagnostics && (!integration || !darwin || !cgo)

package hid

func sleepDiagnosticCapabilities() map[string]bool                      { return map[string]bool{"power-events": false} }
func sleepHardwareDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun { return nil }
