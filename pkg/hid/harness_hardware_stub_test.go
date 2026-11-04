//go:build hid_diagnostics && integration && (!darwin || !cgo)

package hid

func hardwareDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun { return nil }
func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": true}
}
