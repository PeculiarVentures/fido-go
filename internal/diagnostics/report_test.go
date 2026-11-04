package diagnostics_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func TestDiagnosticsSoftwareReportExport(t *testing.T) {
	report := diagnostics.Report{
		SchemaVersion: 1,
		Environment:   diagnostics.Environment{OS: "fixture"},
		Results: []diagnostics.Result{{
			ScenarioID: "fixture", Status: diagnostics.Fail, Reason: "missing evidence",
			Cleanup: diagnostics.Cleanup{Complete: true}, Facts: map[string]bool{"joined": false},
		}},
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.WriteFile(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(path)) {
		t.Fatal("report leaked local path")
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
	if !reflect.DeepEqual(decoded, report) {
		t.Fatalf("JSON round trip changed report: %+v", decoded)
	}
	if err := diagnostics.WriteFile("relative.json", report); err == nil {
		t.Fatal("relative report path accepted")
	}
}
