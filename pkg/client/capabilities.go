package client

import (
	"context"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CTAP1Capabilities describes the detected CTAP1 capability baseline.
type CTAP1Capabilities struct {
	Version string
}

// DeviceCapabilities describes the detected authenticator protocol support.
type DeviceCapabilities struct {
	CTAP1 *CTAP1Capabilities
	CTAP2 *ctap2.GetInfoResponse
}

// HasCTAP1 reports whether CTAP1 support has been detected.
func (caps *DeviceCapabilities) HasCTAP1() bool {
	return caps != nil && caps.CTAP1 != nil
}

// HasCTAP2 reports whether CTAP2 support has been detected.
func (caps *DeviceCapabilities) HasCTAP2() bool {
	return caps != nil && caps.CTAP2 != nil
}

// PreferredProtocol reports the highest-preference detected protocol family.
func (caps *DeviceCapabilities) PreferredProtocol() (protocol.Family, bool) {
	if caps.HasCTAP2() {
		return protocol.FamilyCTAP2, true
	}
	if caps.HasCTAP1() {
		return protocol.FamilyCTAP1, true
	}
	return "", false
}

// GetCapabilities probes the registered protocol families and caches the result.
func (client *client) GetCapabilities(ctx context.Context) (*DeviceCapabilities, error) {
	if client.caps != nil {
		return client.caps, nil
	}

	caps := &DeviceCapabilities{}

	if _, ok := client.invokers[protocol.FamilyCTAP2]; ok {
		request := ctap2.NewGetInfoCommand()
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandGetInfo, nil)
		if err == nil {
			var response ctap2.GetInfoResponse
			if err := request.DecodeResponse(responseBytes, &response); err == nil {
				caps.CTAP2 = &response
			}
		}
	}

	if _, ok := client.invokers[protocol.FamilyCTAP1]; ok {
		request := ctap1.NewVersionCommand()
		responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP1, ctap1.CommandVersion, nil)
		if err == nil {
			var response ctap1.VersionResponse
			if err := request.DecodeResponse(responseBytes, &response); err == nil {
				caps.CTAP1 = &CTAP1Capabilities{Version: response.Version}
			}
		}
	}

	if !caps.HasCTAP1() && !caps.HasCTAP2() {
		return nil, ErrNoCapableProtocol
	}

	client.caps = caps
	return client.caps, nil
}
