//go:build hid_diagnostics

package client_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PeculiarVentures/fido-go/pkg/client"
)

var errClientDiagnosticFileAbsent = errors.New("client diagnostic secure input is absent")

type clientDiagnosticAction struct {
	Phase    string
	TargetID string
	Token    string
	Observe  func(context.Context) error
}
type clientDiagnosticAck struct {
	Phase      string `json:"phase"`
	Token      string `json:"token"`
	TargetID   string `json:"target_id"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Confirm    string `json:"confirm,omitempty"`
	Approve    bool   `json:"approve"`
}

type clientDiagnosticOptions struct {
	Safety                                                       *clientDiagnosticSafety
	Endpoint                                                     string
	Locator                                                      client.Locator
	Hardware, Credentials, Persistence, PINSet, PINChange, Reset bool
	PINFile, NewPINFile, TempPINFile                             string
	Operator                                                     func(context.Context, clientDiagnosticAction) (clientDiagnosticAck, error)
	Output                                                       io.Writer
}

func readClientDiagnosticSecret(path string) (client.Secret, error) {
	data, err := readClientDiagnosticSecureFile(path, 256)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	valid := utf8.Valid(data) && utf8.RuneCount(data) >= 4 && len(data) <= 63
	for _, b := range data {
		if b < 0x20 || b == 0x7f {
			valid = false
		}
	}
	if !valid {
		for index := range data {
			data[index] = 0
		}
		return nil, errors.New("client diagnostic PIN file has invalid bytes or length")
	}
	return client.Secret(data), nil
}

func clientDiagnosticFileOperator(path string, output io.Writer) func(context.Context, clientDiagnosticAction) (clientDiagnosticAck, error) {
	return func(ctx context.Context, action clientDiagnosticAction) (clientDiagnosticAck, error) {
		if !filepath.IsAbs(path) || output == nil || action.TargetID == "" || !clientDiagnosticPhase(action.Phase) {
			return clientDiagnosticAck{}, errors.New("invalid client operator configuration")
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return clientDiagnosticAck{}, errors.New("client operator token generation failed")
		}
		token := action.Token
		if token == "" {
			token = hex.EncodeToString(nonce)
		}
		decoded, decodeTokenErr := hex.DecodeString(token)
		if decodeTokenErr != nil || len(decoded) != 16 {
			return clientDiagnosticAck{}, errors.New("invalid client operator phase token")
		}
		if _, err := fmt.Fprintf(output, "CLIENT_OPERATOR phase=%s token=%s\n", action.Phase, token); err != nil {
			return clientDiagnosticAck{}, errors.New("client operator marker write failed")
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			if action.Observe != nil {
				if err := action.Observe(ctx); err != nil {
					return clientDiagnosticAck{}, err
				}
			}
			data, err := readClientDiagnosticSecureFile(path, 4096)
			if err != nil && !errors.Is(err, errClientDiagnosticFileAbsent) {
				return clientDiagnosticAck{}, err
			}
			if err == nil {
				var ack clientDiagnosticAck
				decoder := json.NewDecoder(strings.NewReader(string(data)))
				decoder.DisallowUnknownFields()
				decodeErr := decoder.Decode(&ack)
				var trailing any
				if decodeErr == nil && decoder.Decode(&trailing) != io.EOF {
					decodeErr = errors.New("invalid trailing client acknowledgment data")
				}
				if decodeErr == nil && ack.Phase == action.Phase && ack.Token == token {
					if ack.TargetID != action.TargetID || !ack.Approve {
						return clientDiagnosticAck{}, errors.New("client operator acknowledgment declined or mismatched exact target")
					}
					if action.Phase == "reset-confirm" && ack.Confirm != "RESET" {
						return clientDiagnosticAck{}, errors.New("client reset requires the exact destructive confirmation")
					}
					if strings.HasSuffix(action.Phase, "replug") && ack.EndpointID == "" {
						return clientDiagnosticAck{}, errors.New("client replug requires explicit exact endpoint enrollment")
					}
					return ack, nil
				}
			}
			select {
			case <-ctx.Done():
				return clientDiagnosticAck{}, ctx.Err()
			case <-ticker.C:
			}
		}
	}
}
func clientDiagnosticPhase(phase string) bool {
	switch phase {
	case "persistence-unplug", "persistence-replug", "reset-confirm", "reset-unplug", "reset-replug":
		return true
	default:
		return false
	}
}
