package tools

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// BlockcheckFormat is the versioned offline blockcheck result format.
	BlockcheckFormat = "desync.blockcheck/v1"
	// BlockcheckZapretRevision is the pinned parity boundary used by the
	// reference procedure.
	BlockcheckZapretRevision = "c849e55ef0f1c244206f5a05ff7b1ab41a3824ee"
	// BlockcheckFlowsealRevision is the pinned regression fixture revision.
	BlockcheckFlowsealRevision = "1.10.4"

	blockcheckMaxReportBytes = 4 << 20
	blockcheckMaxCases       = 4096
	blockcheckMaxIDLength    = 64
	blockcheckMaxTextLength  = 512
)

// BlockcheckStatus is a validated case status.
type BlockcheckStatus string

const (
	BlockcheckPass BlockcheckStatus = "PASS"
	BlockcheckFail BlockcheckStatus = "FAIL"
	BlockcheckSkip BlockcheckStatus = "SKIP"
)

// BlockcheckEvidence is local reference/path metadata supplied by the operator.
// It is never interpreted as packet or application data and the validator never
// opens the artifact.
type BlockcheckEvidence struct {
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
}

// BlockcheckCase is one normalized result case.
type BlockcheckCase struct {
	ID       string             `json:"id"`
	Platform string             `json:"platform"`
	Strategy string             `json:"strategy"`
	Status   BlockcheckStatus   `json:"status"`
	Evidence *BlockcheckEvidence `json:"evidence"`
	Reason   string             `json:"reason"`
}

// BlockcheckReference pins the compared upstream revisions.
type BlockcheckReference struct {
	ZapretRevision   string `json:"zapret_revision"`
	FlowsealRevision string `json:"flowseal_revision"`
}

// BlockcheckReport is a desync.blockcheck/v1 document.
type BlockcheckReport struct {
	Format    string             `json:"format"`
	Reference BlockcheckReference `json:"reference"`
	Cases     []BlockcheckCase   `json:"cases"`
}

var (
	blockcheckIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	blockcheckSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateBlockcheckReport decodes and validates an offline blockcheck result
// document. Unknown fields, duplicate case ids, unknown platforms or statuses,
// a PASS case without evidence and evidence without a sha256 are rejected.
//
// The validator performs no network, packet or application check: a PASS only
// states that the operator supplied evidence metadata for that case.
func ValidateBlockcheckReport(data []byte) (*BlockcheckReport, error) {
	if len(data) == 0 {
		return nil, E.New("blockcheck: empty report")
	}
	if len(data) > blockcheckMaxReportBytes {
		return nil, E.New("blockcheck: report exceeds ", blockcheckMaxReportBytes, " bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report BlockcheckReport
	if err := decoder.Decode(&report); err != nil {
		return nil, E.Cause(err, "blockcheck: decode report")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, E.New("blockcheck: report must contain exactly one JSON document")
		}
		return nil, E.Cause(err, "blockcheck: decode trailing data")
	}
	if report.Format != BlockcheckFormat {
		return nil, E.New("blockcheck: unsupported format ", report.Format, ", want ", BlockcheckFormat)
	}
	if report.Reference.ZapretRevision != BlockcheckZapretRevision {
		return nil, E.New("blockcheck: zapret_revision ", report.Reference.ZapretRevision, " is not the pinned ", BlockcheckZapretRevision)
	}
	if report.Reference.FlowsealRevision != BlockcheckFlowsealRevision {
		return nil, E.New("blockcheck: flowseal_revision ", report.Reference.FlowsealRevision, " is not the pinned ", BlockcheckFlowsealRevision)
	}
	if len(report.Cases) == 0 {
		return nil, E.New("blockcheck: report has no cases")
	}
	if len(report.Cases) > blockcheckMaxCases {
		return nil, E.New("blockcheck: report exceeds the case limit of ", blockcheckMaxCases)
	}
	seen := make(map[string]struct{}, len(report.Cases))
	cases := make([]BlockcheckCase, 0, len(report.Cases))
	for index := range report.Cases {
		blockcheckCase := report.Cases[index]
		if !blockcheckIDPattern.MatchString(blockcheckCase.ID) {
			return nil, E.New("blockcheck: invalid case id ", blockcheckCase.ID)
		}
		if _, duplicate := seen[blockcheckCase.ID]; duplicate {
			return nil, E.New("blockcheck: duplicate case id ", blockcheckCase.ID)
		}
		seen[blockcheckCase.ID] = struct{}{}
		switch blockcheckCase.Platform {
		case "linux", "windows":
		default:
			return nil, E.New("blockcheck: case ", blockcheckCase.ID, " has unsupported platform ", blockcheckCase.Platform)
		}
		if !validBlockcheckText(blockcheckCase.Strategy) {
			return nil, E.New("blockcheck: case ", blockcheckCase.ID, " has an invalid strategy")
		}
		if !validBlockcheckText(blockcheckCase.Reason) {
			return nil, E.New("blockcheck: case ", blockcheckCase.ID, " has an invalid reason")
		}
		switch blockcheckCase.Status {
		case BlockcheckPass:
			if blockcheckCase.Evidence == nil {
				return nil, E.New("blockcheck: PASS case ", blockcheckCase.ID, " has no evidence")
			}
		case BlockcheckFail, BlockcheckSkip:
			if strings.TrimSpace(blockcheckCase.Reason) == "" {
				return nil, E.New("blockcheck: ", string(blockcheckCase.Status), " case ", blockcheckCase.ID, " has no reason")
			}
		default:
			return nil, E.New("blockcheck: case ", blockcheckCase.ID, " has unsupported status ", string(blockcheckCase.Status))
		}
		if blockcheckCase.Evidence != nil {
			if strings.TrimSpace(blockcheckCase.Evidence.Artifact) == "" || !validBlockcheckText(blockcheckCase.Evidence.Artifact) {
				return nil, E.New("blockcheck: case ", blockcheckCase.ID, " has invalid evidence artifact metadata")
			}
			if !blockcheckSHA256Pattern.MatchString(blockcheckCase.Evidence.SHA256) {
				return nil, E.New("blockcheck: case ", blockcheckCase.ID, " evidence sha256 must be 64 lowercase hex characters")
			}
		}
		cases = append(cases, blockcheckCase)
	}
	report.Cases = cases
	return &report, nil
}

// NormalizeBlockcheckReport returns the deterministic encoding of a validated
// report: cases are sorted by platform and id and the JSON is indented with two
// spaces and a trailing newline.
func NormalizeBlockcheckReport(report *BlockcheckReport) ([]byte, error) {
	if report == nil {
		return nil, E.New("blockcheck: nil report")
	}
	normalized := *report
	normalized.Cases = slices.Clone(report.Cases)
	slices.SortStableFunc(normalized.Cases, func(a BlockcheckCase, b BlockcheckCase) int {
		if result := strings.Compare(a.Platform, b.Platform); result != 0 {
			return result
		}
		return strings.Compare(a.ID, b.ID)
	})
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(normalized); err != nil {
		return nil, E.Cause(err, "blockcheck: encode report")
	}
	return buffer.Bytes(), nil
}

// NormalizeBlockcheckReportData validates then normalizes raw report bytes.
func NormalizeBlockcheckReportData(data []byte) ([]byte, *BlockcheckReport, error) {
	report, err := ValidateBlockcheckReport(data)
	if err != nil {
		return nil, nil, err
	}
	normalized, err := NormalizeBlockcheckReport(report)
	if err != nil {
		return nil, nil, err
	}
	return normalized, report, nil
}

func validBlockcheckText(text string) bool {
	if len(text) > blockcheckMaxTextLength {
		return false
	}
	for index := 0; index < len(text); index++ {
		if text[index] < 0x20 || text[index] == 0x7f {
			return false
		}
	}
	return true
}
