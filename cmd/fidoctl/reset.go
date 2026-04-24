package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

const resetConfirmationValue = "RESET"

var errResetConfirmationRequired = errors.New("reset confirmation required")

func newResetCommand(deps cliDependencies) *cobra.Command {
	var force bool
	command := &cobra.Command{
		Use:   "reset",
		Short: "Reset a CTAP2 authenticator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			if err := confirmReset(deps.stdin, deps.stderr, !deps.flags.noInteractive, force); err != nil {
				return err
			}

			if err := deps.service.Reset(ctx, deps.flags.deviceID); err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, map[string]bool{"reset": true}, func(writer io.Writer) error {
				_, err := fmt.Fprintln(writer, "reset completed")
				return err
			})
		},
	}
	command.Flags().BoolVar(&force, "yes", false, "Skip the reset confirmation prompt")
	return command
}

func confirmReset(stdin io.Reader, stderr io.Writer, interactive bool, force bool) error {
	if force {
		return nil
	}
	if !interactive {
		return fmt.Errorf("%w: rerun with --yes when using --no-interactive", errResetConfirmationRequired)
	}
	if _, err := fmt.Fprintf(stderr, "Reset will permanently erase authenticator state. Type %q to continue: ", resetConfirmationValue); err != nil {
		return err
	}
	reader := bufio.NewReader(stdin)
	confirmation, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read reset confirmation: %w", err)
	}
	if strings.TrimSpace(confirmation) != resetConfirmationValue {
		return fmt.Errorf("%w: destructive reset aborted", errResetConfirmationRequired)
	}
	return nil
}
