package main

import (
	"fmt"
	"io"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

func newPinCommand(deps cliDependencies) *cobra.Command {
	command := &cobra.Command{Use: "pin", Short: "Manage the authenticator PIN"}
	retries := &cobra.Command{
		Use:   "retries",
		Short: "Show remaining PIN retries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			result, err := deps.service.PINRetries(ctx, deps.flags.deviceID)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				return writePINRetriesHuman(writer, result)
			})
		},
	}

	var setPINEnv string
	var setPINStdin bool
	set := &cobra.Command{
		Use:   "set",
		Short: "Set the authenticator PIN",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			secretInput := newSecretInput(deps.stdin)
			resolvedNewPIN, err := secretInput.Resolve(secretRequest{
				EnvName:    setPINEnv,
				DefaultEnv: "FIDO_NEW_PIN",
				ReadStdin:  setPINStdin,
				Missing:    client.ErrNewPINRequired,
				Label:      "new pin",
			})
			if err != nil {
				return err
			}
			defer resolvedNewPIN.Wipe()

			if err := deps.service.SetPIN(ctx, deps.flags.deviceID, resolvedNewPIN); err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, map[string]bool{"set": true}, func(writer io.Writer) error {
				_, err := fmt.Fprintln(writer, "PIN set")
				return err
			})
		},
	}
	set.Flags().StringVar(&setPINEnv, "new-pin-env", "", "Read the new PIN from the specified environment variable")
	set.Flags().BoolVar(&setPINStdin, "new-pin-stdin", false, "Read the new PIN from stdin")

	var currentPINEnv string
	var currentPINStdin bool
	var newPINEnv string
	var newPINStdin bool
	change := &cobra.Command{
		Use:   "change",
		Short: "Change the authenticator PIN",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			secretInput := newSecretInput(deps.stdin)
			resolvedCurrentPIN, err := secretInput.Resolve(secretRequest{
				EnvName:    currentPINEnv,
				DefaultEnv: "FIDO_PIN",
				ReadStdin:  currentPINStdin,
				Missing:    client.ErrPINRequired,
				Label:      "current pin",
			})
			if err != nil {
				return err
			}
			defer resolvedCurrentPIN.Wipe()

			resolvedNewPIN, err := secretInput.Resolve(secretRequest{
				EnvName:    newPINEnv,
				DefaultEnv: "FIDO_NEW_PIN",
				ReadStdin:  newPINStdin,
				Missing:    client.ErrNewPINRequired,
				Label:      "new pin",
			})
			if err != nil {
				return err
			}
			defer resolvedNewPIN.Wipe()

			if err := deps.service.ChangePIN(ctx, deps.flags.deviceID, resolvedCurrentPIN, resolvedNewPIN); err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, map[string]bool{"changed": true}, func(writer io.Writer) error {
				_, err := fmt.Fprintln(writer, "PIN changed")
				return err
			})
		},
	}
	change.Flags().StringVar(&currentPINEnv, "old-pin-env", "", "Read the current PIN from the specified environment variable")
	change.Flags().BoolVar(&currentPINStdin, "old-pin-stdin", false, "Read the current PIN from stdin")
	change.Flags().StringVar(&newPINEnv, "new-pin-env", "", "Read the new PIN from the specified environment variable")
	change.Flags().BoolVar(&newPINStdin, "new-pin-stdin", false, "Read the new PIN from stdin")

	command.AddCommand(retries)
	command.AddCommand(set)
	command.AddCommand(change)
	return command
}
