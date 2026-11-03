//go:build hid_diagnostics && (!darwin || !cgo)

package hid

func platformDiagnosticRuns(hidDiagnosticsOptions) []diagnosticRun { return nil }
func platformDiagnosticCapabilities() map[string]bool              { return map[string]bool{"darwin-cgo": false} }
