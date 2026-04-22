package client

import (
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// Device aliases the public transport device descriptor for facade consumers.
type Device = transport.DeviceDescriptor

// ProtocolFamily aliases the public protocol-family type for facade consumers.
type ProtocolFamily = protocol.Family

const (
	// FamilyCTAP1 identifies the CTAP1/U2F protocol family.
	FamilyCTAP1 ProtocolFamily = protocol.FamilyCTAP1
	// FamilyCTAP2 identifies the CTAP2 protocol family.
	FamilyCTAP2 ProtocolFamily = protocol.FamilyCTAP2
)
