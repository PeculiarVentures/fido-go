package main

import (
	"io"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

func newCredentialsCommand(deps cliDependencies) *cobra.Command {
	creds := &cobra.Command{Use: "credentials", Aliases: []string{"creds"}, Short: "Manage discoverable credentials"}
	var pinEnv string
	var pinStdin bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List discoverable credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			secretInput := newSecretInput(deps.stdin)
			resolvedPIN, err := secretInput.Resolve(secretRequest{
				EnvName:    pinEnv,
				DefaultEnv: "FIDO_PIN",
				ReadStdin:  pinStdin,
				Missing:    client.ErrPINRequired,
				Label:      "pin",
			})
			if err != nil {
				return err
			}
			defer resolvedPIN.Wipe()

			result, err := deps.service.ListCredentials(ctx, deps.flags.deviceID, resolvedPIN)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				return writeCredentialTable(writer, result)
			})
		},
	}
	list.Flags().StringVar(&pinEnv, "pin-env", "", "Read the PIN from the specified environment variable")
	list.Flags().BoolVar(&pinStdin, "pin-stdin", false, "Read the PIN from stdin")
	creds.AddCommand(list)
	return creds
}
