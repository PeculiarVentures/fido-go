package main

import (
	"context"
	"fmt"
	"io"
	"time"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/spf13/cobra"
)

type globalFlags struct {
	deviceID      string
	nfc           bool
	timeout       time.Duration
	format        string
	jsonOutput    bool
	verbose       bool
	debug         bool
	noInteractive bool
}

type cliDependencies struct {
	service fidoctl.Service
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	version string
	flags   *globalFlags
}

type interactionConfigurer interface {
	ConfigureInteraction(interactive bool, status io.Writer)
}

type transportPreferenceConfigurer interface {
	ConfigureTransportPreferences(preference client.TransportPreference) error
}

func newRootCommand(deps cliDependencies) *cobra.Command {
	root := &cobra.Command{
		Use:           "fidoctl",
		Short:         "FIDO authenticator command-line interface",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if deps.flags.jsonOutput {
				deps.flags.format = "json"
			}
			if configurer, ok := deps.service.(transportPreferenceConfigurer); ok {
				if err := configurer.ConfigureTransportPreferences(client.TransportPreference{USB: true, NFC: deps.flags.nfc}); err != nil {
					return err
				}
			}
			if configurer, ok := deps.service.(interactionConfigurer); ok {
				configurer.ConfigureInteraction(!deps.flags.noInteractive, deps.stderr)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	root.PersistentFlags().StringVar(&deps.flags.deviceID, "device-id", "", "Select a specific device; defaults to the first discovered authenticator")
	root.PersistentFlags().BoolVar(&deps.flags.nfc, "nfc", false, "Enable NFC/PCSC discovery in addition to USB HID")
	root.PersistentFlags().DurationVar(&deps.flags.timeout, "timeout", 30*time.Second, "Command timeout")
	root.PersistentFlags().StringVar(&deps.flags.format, "format", "human", "Output format: human, json, raw")
	root.PersistentFlags().BoolVar(&deps.flags.jsonOutput, "json", false, "Emit JSON to stdout")
	root.PersistentFlags().BoolVar(&deps.flags.verbose, "verbose", false, "Enable verbose output")
	root.PersistentFlags().BoolVar(&deps.flags.debug, "debug", false, "Enable debug output")
	root.PersistentFlags().BoolVar(&deps.flags.noInteractive, "no-interactive", false, "Disable interactive prompts")

	root.AddCommand(
		newDevicesCommand(deps),
		newInfoCommand(deps),
		newRawCommand(deps),
		newTraceCommand(deps),
		newPinCommand(deps),
		newRegisterCommand(deps),
		newAuthenticateCommand(deps),
		newResetCommand(deps),
		newCredentialsCommand(deps),
		newVersionCommand(deps),
	)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func newDevicesCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:     "devices",
		Aliases: []string{"list"},
		Short:   "List discovered authenticators",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			devices, err := deps.service.ListDevices(ctx)
			if err != nil && len(devices) == 0 {
				return err
			}
			if err != nil {
				_, _ = fmt.Fprintf(deps.stderr, "warning: %v\n", err)
			}
			return writeValue(deps.stdout, deps.flags.format, devices, func(writer io.Writer) error {
				return writeDeviceTable(writer, devices)
			})
		},
	}
}

func newInfoCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show capabilities for one authenticator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := withTimeout(deps.flags.timeout)
			defer cancel()

			result, err := deps.service.Info(ctx, deps.flags.deviceID)
			if err != nil {
				return err
			}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				return writeInfoHuman(writer, result)
			})
		},
	}
}

func newVersionCommand(deps cliDependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			result := map[string]string{"binary": "fidoctl", "version": deps.version}
			return writeValue(deps.stdout, deps.flags.format, result, func(writer io.Writer) error {
				_, err := fmt.Fprintf(writer, "fidoctl %s\n", deps.version)
				return err
			})
		},
	}
}

func withTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
}
