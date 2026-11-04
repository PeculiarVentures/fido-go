//go:build hid_diagnostics && !integration

package hid

func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": false}
}
func hardwareDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun         { return nil }
func portableHardwareDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun { return nil }
func supplementalHardwareDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun {
	return nil
}
