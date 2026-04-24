package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	fidoctl "github.com/PeculiarVentures/fido-go/internal/cli/fidoctl"
	"github.com/PeculiarVentures/fido-go/pkg/client"
)

func writeDeviceTable(writer io.Writer, devices []client.Device) error {
	if len(devices) == 0 {
		_, err := fmt.Fprintln(writer, "No devices found")
		return err
	}
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "ID\tTRANSPORT\tPRODUCT\tSERIAL")
	for _, device := range devices {
		serial := "-"
		if device.SerialNumber != "" {
			serial = device.SerialNumber
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", device.ID, device.Transport, deviceLabel(device), serial)
	}
	return table.Flush()
}

func writeInfoHuman(writer io.Writer, result *fidoctl.InfoResult) error {
	if result == nil {
		_, err := fmt.Fprintln(writer, "No authenticator information available")
		return err
	}
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	preferred := "unknown"
	if family, ok := result.Capabilities.PreferredProtocol(); ok {
		preferred = string(family)
	}
	_, _ = fmt.Fprintf(table, "Device\t%s\n", result.Device.DisplayName())
	_, _ = fmt.Fprintf(table, "ID\t%s\n", result.Device.ID)
	_, _ = fmt.Fprintf(table, "Transport\t%s\n", result.Device.Transport)
	_, _ = fmt.Fprintf(table, "Preferred\t%s\n", preferred)
	if result.Device.Manufacturer != "" {
		_, _ = fmt.Fprintf(table, "Manufacturer\t%s\n", result.Device.Manufacturer)
	}
	if result.Device.Product != "" {
		_, _ = fmt.Fprintf(table, "Product\t%s\n", result.Device.Product)
	}
	if result.Device.SerialNumber != "" {
		_, _ = fmt.Fprintf(table, "Serial\t%s\n", result.Device.SerialNumber)
	}
	if result.Device.Path != "" && result.Device.Path != result.Device.ID {
		_, _ = fmt.Fprintf(table, "Path\t%s\n", result.Device.Path)
	}
	if result.Capabilities != nil && result.Capabilities.RawCTAP1 != nil {
		_, _ = fmt.Fprintf(table, "CTAP1 Version\t%s\n", result.Capabilities.RawCTAP1.Version)
	}
	if result.Capabilities != nil && result.Capabilities.RawCTAP2 != nil {
		info := result.Capabilities.RawCTAP2
		if len(info.Versions) > 0 {
			_, _ = fmt.Fprintf(table, "CTAP2 Versions\t%s\n", strings.Join(info.Versions, ", "))
		}
		if len(info.Extensions) > 0 {
			_, _ = fmt.Fprintf(table, "CTAP2 Extensions\t%s\n", strings.Join(info.Extensions, ", "))
		}
		if len(info.Transports) > 0 {
			_, _ = fmt.Fprintf(table, "CTAP2 Transports\t%s\n", strings.Join(info.Transports, ", "))
		}
		if len(info.PinUVAuthProtocols) > 0 {
			_, _ = fmt.Fprintf(table, "PIN/UV Protocols\t%s\n", formatUint64List(info.PinUVAuthProtocols))
		}
		if len(info.AAGUID) > 0 {
			_, _ = fmt.Fprintf(table, "AAGUID\t%s\n", hex.EncodeToString(info.AAGUID))
		}
		if info.MaxMsgSize > 0 {
			_, _ = fmt.Fprintf(table, "Max Message Size\t%d\n", info.MaxMsgSize)
		}
		if info.MaxCredentialIDLength > 0 {
			_, _ = fmt.Fprintf(table, "Max Credential ID Length\t%d\n", info.MaxCredentialIDLength)
		}
		if info.MaxCredentialCountInList > 0 {
			_, _ = fmt.Fprintf(table, "Max Credential Count\t%d\n", info.MaxCredentialCountInList)
		}
	}
	if result.PINRetries != nil {
		_, _ = fmt.Fprintf(table, "PIN Retries\t%d\n", result.PINRetries.PINRetries)
		if result.PINRetries.UVRetries > 0 {
			_, _ = fmt.Fprintf(table, "UV Retries\t%d\n", result.PINRetries.UVRetries)
		}
		if result.PINRetries.PowerCycleState {
			_, _ = fmt.Fprintf(table, "Power Cycle Required\ttrue\n")
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if result.Capabilities != nil && result.Capabilities.RawCTAP2 != nil && len(result.Capabilities.RawCTAP2.Options) > 0 {
		if _, err := fmt.Fprintln(writer, "Options:"); err != nil {
			return err
		}
		for _, key := range sortedOptionKeys(result.Capabilities.RawCTAP2.Options) {
			if _, err := fmt.Fprintf(writer, "  %s=%t\n", key, result.Capabilities.RawCTAP2.Options[key]); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeCredentialTable(writer io.Writer, result *fidoctl.CredentialListResult) error {
	if result == nil || result.Credentials == nil || len(result.Credentials.Credentials) == 0 {
		_, err := fmt.Fprintln(writer, "No discoverable credentials found")
		return err
	}
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "RP ID\tUSER\tCREDENTIAL ID\tPROTECT")
	for _, credential := range result.Credentials.Credentials {
		protect := "-"
		if credential.CredProtect != 0 {
			protect = strconv.FormatUint(credential.CredProtect, 10)
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", credential.RP.ID, credentialUserLabel(credential), hex.EncodeToString(credential.Credential.ID), protect)
	}
	return table.Flush()
}

func writePINRetriesHuman(writer io.Writer, result *fidoctl.PINRetriesResult) error {
	if result == nil || result.PINRetries == nil {
		_, err := fmt.Fprintln(writer, "No PIN retry information available")
		return err
	}
	table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(table, "Device\t%s\n", result.Device.DisplayName())
	_, _ = fmt.Fprintf(table, "ID\t%s\n", result.Device.ID)
	_, _ = fmt.Fprintf(table, "PIN Retries\t%d\n", result.PINRetries.PINRetries)
	if result.PINRetries.UVRetries > 0 {
		_, _ = fmt.Fprintf(table, "UV Retries\t%d\n", result.PINRetries.UVRetries)
	}
	if result.PINRetries.PowerCycleState {
		_, _ = fmt.Fprintf(table, "Power Cycle Required\ttrue\n")
	}
	return table.Flush()
}

func credentialUserLabel(credential client.DiscoverableCredential) string {
	switch {
	case credential.User.DisplayName != "":
		return credential.User.DisplayName
	case credential.User.Name != "":
		return credential.User.Name
	case len(credential.User.ID) > 0:
		return hex.EncodeToString(credential.User.ID)
	default:
		return "-"
	}
}

func deviceLabel(device client.Device) string {
	switch {
	case device.Manufacturer != "" && device.Product != "":
		return device.Manufacturer + " " + device.Product
	case device.Product != "":
		return device.Product
	default:
		return device.DisplayName()
	}
}

func formatUint64List(values []uint64) string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, strconv.FormatUint(value, 10))
	}
	return strings.Join(formatted, ", ")
}

func sortedOptionKeys(options map[string]bool) []string {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeValue(writer io.Writer, format string, value any, human func(io.Writer) error) error {
	switch format {
	case "human":
		return human(writer)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeRawValue(writer io.Writer, format string, raw []byte, value any, human func(io.Writer) error) error {
	if format == "raw" {
		_, err := writer.Write(raw)
		return err
	}
	return writeValue(writer, format, value, human)
}
