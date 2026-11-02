package hid

// ReportSpec is a fixed report format. Size excludes the Report ID.
type ReportSpec struct {
	ID   uint8
	Size int
}

// ReportLayout contains the collection's unique Input and Output formats.
type ReportLayout struct {
	Input  ReportSpec
	Output ReportSpec
}

// Report contains an ID separately from its data bytes.
type Report struct {
	ID   uint8
	Data []byte
}

// WriteOutcome reports native delivery, without claiming command execution.
type WriteOutcome uint8

const (
	OutcomeUnknown WriteOutcome = iota
	OutcomeNotSubmitted
	OutcomeCompleted
)

// WriteResult remains meaningful even when Write also returns an error.
type WriteResult struct{ Outcome WriteOutcome }
