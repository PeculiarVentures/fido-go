package main

import (
	"fmt"
	"io"

	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

func newRegisterCommand(deps cliDependencies) *cobra.Command {
	var challengeFlag string
	var rpIDFlag string
	var rpNameFlag string
	var userIDFlag string
	var userNameFlag string
	var userDisplayNameFlag string
	var appIDHashFlag string
	command := &cobra.Command{
		Use:   "register",
		Short: "Run a basic registration flow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			challengeHash, err := decodeBinary(challengeFlag)
			if err != nil {
				return err
			}
			userID, err := decodeBinary(userIDFlag)
			if err != nil {
				return err
			}
			appIDHash, err := decodeOptionalBinary(appIDHashFlag)
			if err != nil {
				return err
			}

			request := client.RegistrationRequest{
				ChallengeHash: challengeHash,
				RPID:          rpIDFlag,
				User: client.User{
					ID:          userID,
					Name:        userNameFlag,
					DisplayName: userDisplayNameFlag,
				},
			}
			if rpNameFlag != "" {
				request.CTAP2 = &client.CTAP2RegistrationOptions{RPName: rpNameFlag}
			}
			if len(appIDHash) != 0 {
				request.CTAP1 = &client.CTAP1RegistrationOptions{AppIDHash: appIDHash}
			}

			result, err := deps.service.Register(ctx, deps.flags.deviceID, request)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "registration completed via %s\n", result.Protocol)
				return err
			})
		},
	}
	command.Flags().StringVar(&challengeFlag, "challenge", "", "Challenge hash in hex or base64")
	command.Flags().StringVar(&rpIDFlag, "rp-id", "", "Relying party identifier")
	command.Flags().StringVar(&rpNameFlag, "rp-name", "", "Relying party display name")
	command.Flags().StringVar(&userIDFlag, "user-id", "", "User identifier in hex or base64")
	command.Flags().StringVar(&userNameFlag, "user-name", "", "User name")
	command.Flags().StringVar(&userDisplayNameFlag, "user-display-name", "", "User display name")
	command.Flags().StringVar(&appIDHashFlag, "app-id-hash", "", "CTAP1 app id hash in hex or base64")
	return command
}

func newAuthenticateCommand(deps cliDependencies) *cobra.Command {
	var challengeFlag string
	var rpIDFlag string
	var appIDHashFlag string
	var keyHandleFlag string
	command := &cobra.Command{
		Use:   "authenticate",
		Short: "Run a basic authentication flow",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			challengeHash, err := decodeBinary(challengeFlag)
			if err != nil {
				return err
			}
			appIDHash, err := decodeOptionalBinary(appIDHashFlag)
			if err != nil {
				return err
			}
			keyHandle, err := decodeOptionalBinary(keyHandleFlag)
			if err != nil {
				return err
			}

			request := client.AuthenticationRequest{
				ChallengeHash: challengeHash,
				RPID:          rpIDFlag,
			}
			if len(appIDHash) != 0 || len(keyHandle) != 0 {
				request.CTAP1 = &client.CTAP1AuthenticationOptions{
					AppIDHash: appIDHash,
					KeyHandle: keyHandle,
				}
			}

			result, err := deps.service.Authenticate(ctx, deps.flags.deviceID, request)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "authentication completed via %s\n", result.Protocol)
				return err
			})
		},
	}
	command.Flags().StringVar(&challengeFlag, "challenge", "", "Challenge hash in hex or base64")
	command.Flags().StringVar(&rpIDFlag, "rp-id", "", "Relying party identifier")
	command.Flags().StringVar(&appIDHashFlag, "app-id-hash", "", "CTAP1 app id hash in hex or base64")
	command.Flags().StringVar(&keyHandleFlag, "key-handle", "", "CTAP1 key handle in hex or base64")
	return command
}
