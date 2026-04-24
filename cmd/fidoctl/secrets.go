package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"golang.org/x/term"
)

type secretRequest struct {
	Value      string
	EnvName    string
	DefaultEnv string
	ReadStdin  bool
	Missing    error
	Label      string
}

type secretInput struct {
	stdin  io.Reader
	reader *bufio.Reader
}

func newSecretInput(stdin io.Reader) *secretInput {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	return &secretInput{stdin: stdin, reader: bufio.NewReader(stdin)}
}

func (input *secretInput) Resolve(request secretRequest) (client.Secret, error) {
	if request.Value != "" {
		return client.NewSecretString(request.Value), nil
	}
	envName := request.EnvName
	if envName == "" {
		envName = request.DefaultEnv
	}
	if envName != "" {
		if value, ok := os.LookupEnv(envName); ok && value != "" {
			return client.NewSecretString(value), nil
		}
	}
	if request.ReadStdin {
		value, err := input.readSecret(request.Label)
		if err != nil {
			return nil, err
		}
		if len(value) != 0 {
			return client.NewSecret(value), nil
		}
	}
	if request.Missing != nil {
		return nil, request.Missing
	}
	return nil, nil
}

func (input *secretInput) readSecret(label string) ([]byte, error) {
	if file, ok := input.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		if err != nil {
			if label == "" {
				label = "secret"
			}
			return nil, fmt.Errorf("read %s from stdin: %w", label, err)
		}
		_, _ = fmt.Fprintln(os.Stderr)
		return bytes.TrimRight(value, "\r\n"), nil
	}
	value, err := input.reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		if label == "" {
			label = "secret"
		}
		return nil, fmt.Errorf("read %s from stdin: %w", label, err)
	}
	return bytes.TrimRight(value, "\r\n"), nil
}
