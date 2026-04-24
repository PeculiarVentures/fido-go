package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PeculiarVentures/fido-go/pkg/client"
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
	reader *bufio.Reader
}

func newSecretInput(stdin io.Reader) *secretInput {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	return &secretInput{reader: bufio.NewReader(stdin)}
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
		value, err := input.readLine(request.Label)
		if err != nil {
			return nil, err
		}
		if value != "" {
			return client.NewSecretString(value), nil
		}
	}
	if request.Missing != nil {
		return nil, request.Missing
	}
	return nil, nil
}

func (input *secretInput) readLine(label string) (string, error) {
	value, err := input.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		if label == "" {
			label = "secret"
		}
		return "", fmt.Errorf("read %s from stdin: %w", label, err)
	}
	return strings.TrimRight(value, "\r\n"), nil
}
