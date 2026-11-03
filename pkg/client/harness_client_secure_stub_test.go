//go:build hid_diagnostics && !darwin && !linux

package client_test

import "errors"

func clientDiagnosticSecureInputAvailable() bool { return false }
func readClientDiagnosticSecureFile(string, int) ([]byte, error) {
	return nil, errors.New("secure owner-only diagnostic input is unsupported on this platform")
}
