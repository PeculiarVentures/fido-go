package usb

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

// ExchangeStage identifies the CTAPHID phase in which an exchange failed.
type ExchangeStage string

const (
	StageINIT     ExchangeStage = "INIT"
	StagePING     ExchangeStage = "PING"
	StageRequest  ExchangeStage = "request"
	StageResponse ExchangeStage = "response"
)

// ExchangeError preserves delivery evidence for one failed CTAPHID transaction.
// PacketsSubmitted counts confirmed native completions, and Outcome describes
// the latest write. Ambiguous means the command may have partially or fully
// reached the authenticator without a definitive CTAPHID response. No field
// grants permission to replay an application command.
type ExchangeError struct {
	Stage            ExchangeStage
	PacketsSubmitted int
	Outcome          hid.WriteOutcome
	Ambiguous        bool
	Cause            error
}

// Error reports the failed stage without logging report data.
func (err *ExchangeError) Error() string {
	return fmt.Sprintf("transport/usb: %s failed after %d completed packets (outcome %d, ambiguous %t): %v", err.Stage, err.PacketsSubmitted, err.Outcome, err.Ambiguous, err.Cause)
}

// Unwrap preserves transport, native, context and CTAPHID error causes.
func (err *ExchangeError) Unwrap() error { return err.Cause }

type exchangeProgress struct {
	stage     ExchangeStage
	packets   int
	outcome   hid.WriteOutcome
	ambiguous bool
}

func (progress *exchangeProgress) wrap(err error) error {
	return &ExchangeError{Stage: progress.stage, PacketsSubmitted: progress.packets, Outcome: progress.outcome, Ambiguous: progress.ambiguous, Cause: err}
}
