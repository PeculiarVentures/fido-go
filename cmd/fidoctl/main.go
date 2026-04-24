package main

import (
	"fmt"
	"os"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
)

var version = "dev"

func main() {
	service, err := fidoctl.NewDefault()
	if err != nil {
		_ = writeCommandError(os.Stderr, "human", err)
		os.Exit(exitGeneralError)
	}
	flags := &globalFlags{}
	command := newRootCommand(cliDependencies{
		service: service,
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		version: version,
		flags:   flags,
	})
	if err := command.Execute(); err != nil {
		exitCode := classifyError(err)
		if writeErr := writeCommandError(os.Stderr, flags.format, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(exitCode)
	}
	os.Exit(exitSuccess)
}
