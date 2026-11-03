//go:build hid_diagnostics && (darwin || linux)

package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTerraSecureDiagnosticInput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "input")
	if err := os.WriteFile(file, []byte("12345678\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientDiagnosticSecret(file); err != nil {
		t.Fatalf("valid owner-only file: %v", err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientDiagnosticSecret(file); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientDiagnosticSecret(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := readClientDiagnosticSecureFile(dir, 256); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := readClientDiagnosticSecureFile("relative", 256); err == nil {
		t.Fatal("relative input accepted")
	}
}

func TestTerraSecureInputRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readClientDiagnosticSecureFile(path, 256); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("opening FIFO blocked")
	}
}

func TestTerraOperatorRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ack")
	markers := make(chan string, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := clientDiagnosticFileOperator(path, terraMarkerWriter{markers})(ctx, clientDiagnosticAction{Phase: "reset-confirm", TargetID: "private-marker"})
		result <- err
	}()
	marker := <-markers
	fields := strings.Fields(marker)
	if len(fields) != 3 {
		t.Fatal("invalid marker")
	}
	ack := clientDiagnosticAck{Phase: "reset-confirm", Token: strings.TrimPrefix(fields[2], "token="), TargetID: "private-marker", Confirm: "RESET", Approve: true}
	data, _ := json.Marshal(ack)
	data = append(data, []byte(" {}")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("trailing JSON acknowledged, err=%v", err)
	}
}

type terraMarkerWriter struct{ markers chan string }

func (w terraMarkerWriter) Write(p []byte) (int, error) { w.markers <- string(p); return len(p), nil }

func TestTerraOperatorRejectsStaleAndMismatchedAcknowledgements(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		amend       func(*clientDiagnosticAck)
	}{
		{"wrong target", "persistence-unplug", func(a *clientDiagnosticAck) { a.TargetID = "other" }},
		{"reset without confirmation", "reset-confirm", func(a *clientDiagnosticAck) { a.Confirm = "" }},
		{"replug without enrollment", "persistence-replug", func(a *clientDiagnosticAck) { a.EndpointID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ack")
			stale := clientDiagnosticAck{Phase: tc.phase, Token: strings.Repeat("0", 32), TargetID: "private-selector-marker", Approve: true}
			encoded, _ := json.Marshal(stale)
			if err := os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			markers := make(chan string, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := clientDiagnosticFileOperator(path, terraMarkerWriter{markers})(ctx, clientDiagnosticAction{Phase: tc.phase, TargetID: "private-selector-marker"})
				result <- err
			}()
			marker := <-markers
			if strings.Contains(marker, "private-selector-marker") {
				t.Fatal("operator marker leaked target")
			}
			fields := strings.Fields(marker)
			if len(fields) != 3 || !strings.HasPrefix(fields[2], "token=") {
				t.Fatalf("invalid marker format: %q", marker)
			}
			select {
			case err := <-result:
				t.Fatalf("stale acknowledgment completed operation: %v", err)
			default:
			}
			ack := clientDiagnosticAck{Phase: tc.phase, Token: strings.TrimPrefix(fields[2], "token="), TargetID: "private-selector-marker", EndpointID: "new-selector", Confirm: "RESET", Approve: true}
			tc.amend(&ack)
			encoded, _ = json.Marshal(ack)
			tmp := path + ".new"
			if err := os.WriteFile(tmp, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil || errors.Is(err, context.DeadlineExceeded) || bytes.Contains([]byte(err.Error()), []byte("private-selector-marker")) {
				t.Fatalf("invalid acknowledgment error: %v", err)
			}
		})
	}
}
