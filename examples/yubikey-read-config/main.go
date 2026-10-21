// Command yubikey-read-config reads the first Yubico Management configuration
// page over an existing FIDO HID session. It does not write configuration.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/client"
)

func main() {
	deviceID := flag.String("device-id", "", "FIDO HID ID of the YubiKey (from fidoctl devices)")
	flag.Parse()
	if err := run(*deviceID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(deviceID string) error {
	if deviceID == "" {
		return fmt.Errorf("-device-id is required; select a YubiKey from fidoctl devices")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locator, err := client.NewDefaultLocator()
	if err != nil {
		return err
	}
	// Explicit HID exchange requires neither CTAP2 probing nor raw invokers.
	sdk, err := locator.Open(ctx, deviceID)
	if err != nil {
		return err
	}
	defer sdk.Close()
	if sdk.Device().VendorID != 0x1050 {
		return fmt.Errorf("selected endpoint is not a Yubico device")
	}
	response, err := readConfig(ctx, sdk)
	if err != nil {
		return fmt.Errorf("Yubico READ_CONFIG: %w", err)
	}
	fmt.Println(hex.EncodeToString(response))
	return nil
}

func readConfig(ctx context.Context, sdk client.Client) ([]byte, error) {
	const readConfigCommand byte = 0x42
	// The one-byte payload selects page zero. The command is not part of it.
	response, err := client.ExchangeHID(ctx, sdk, readConfigCommand, []byte{0x00})
	if err != nil {
		return nil, err
	}
	// The vendor response is a length byte followed by TLV data. Any further
	// parsing and pagination belong in the application/vendor adapter.
	if len(response) == 0 || int(response[0]) != len(response)-1 {
		return nil, fmt.Errorf("invalid Yubico configuration response length")
	}
	return response, nil
}
