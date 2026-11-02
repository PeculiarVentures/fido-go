//go:build hid_diagnostics

package hid

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func TestDiagnosticsSoftwareReportExport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := runHIDDiagnostics(ctx, hidDiagnosticsOptions{EndpointIDs: []EndpointID{"private-endpoint-sentinel"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeDiagnosticReport(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(path)) || bytes.Contains(data, []byte("private-endpoint-sentinel")) {
		t.Fatal("report leaked local path or endpoint selector")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("report mode=%o", info.Mode().Perm())
	}
	var decoded diagnostics.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != 1 {
		t.Fatalf("schema version=%d", decoded.SchemaVersion)
	}
	requireDiagnosticScenarios(t, decoded, expectedDeterministicDiagnosticIDs())
	assertNativeDiagnosticEvidence(t, decoded)
	if err := writeDiagnosticReport("relative.json", report); err == nil {
		t.Fatal("relative report path accepted")
	}
}
