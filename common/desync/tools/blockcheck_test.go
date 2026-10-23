package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

func validBlockcheckJSON(status string, evidence string, reason string) string {
	return `{"format":"desync.blockcheck/v1",` +
		`"reference":{"zapret_revision":"` + BlockcheckZapretRevision + `","flowseal_revision":"` + BlockcheckFlowsealRevision + `"},` +
		`"cases":[{"id":"linux-tls-fake","platform":"linux","strategy":"fake","status":"` + status + `",` +
		`"evidence":` + evidence + `,"reason":` + strconvQuote(reason) + `}]}`
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

var validEvidence = `{"artifact":"testdata/blockcheck/synthetic.pcap","sha256":"` + strings.Repeat("a", 64) + `"}`

func TestValidateBlockcheckReport(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"PASS", "FAIL", "SKIP"} {
		status := status
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			report, err := ValidateBlockcheckReport([]byte(validBlockcheckJSON(status, validEvidence, "supplied evidence")))
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Cases) != 1 || string(report.Cases[0].Status) != status {
				t.Fatalf("unexpected report %+v", report)
			}
		})
	}
}

func TestValidateBlockcheckReportRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		reason string
	}{
		{"unknown top level field", `{"format":"desync.blockcheck/v1","reference":{"zapret_revision":"` + BlockcheckZapretRevision + `","flowseal_revision":"` + BlockcheckFlowsealRevision + `"},"cases":[],"extra":1}`, "unknown field"},
		{"unknown case field", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), `"reason":""`, `"reason":"","packets":1`, 1), "unknown field"},
		{"unknown evidence field", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), `"sha256"`, `"bytes":1,"sha256"`, 1), "unknown field"},
		{"wrong format", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), "desync.blockcheck/v1", "desync.blockcheck/v0", 1), "unsupported format"},
		{"wrong zapret revision", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), BlockcheckZapretRevision, "deadbeef", 1), "not the pinned"},
		{"wrong flowseal revision", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), BlockcheckFlowsealRevision, "1.11.0", 1), "not the pinned"},
		{"pass without evidence", validBlockcheckJSON("PASS", "null", ""), "has no evidence"},
		{"evidence without artifact", validBlockcheckJSON("PASS", `{"artifact":"","sha256":"`+strings.Repeat("a", 64)+`"}`, ""), "invalid evidence artifact"},
		{"evidence with short hash", validBlockcheckJSON("PASS", `{"artifact":"x.pcap","sha256":"abc"}`, ""), "sha256"},
		{"fail without reason", validBlockcheckJSON("FAIL", validEvidence, ""), "has no reason"},
		{"skip without reason", validBlockcheckJSON("SKIP", "null", ""), "has no reason"},
		{"unknown status", validBlockcheckJSON("MAYBE", validEvidence, "x"), "unsupported status"},
		{"unknown platform", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), `"platform":"linux"`, `"platform":"darwin"`, 1), "unsupported platform"},
		{"invalid id", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), `"id":"linux-tls-fake"`, `"id":"Bad ID"`, 1), "invalid case id"},
		{"duplicate id", strings.Replace(validBlockcheckJSON("PASS", validEvidence, ""), `"cases":[`, `"cases":[{"id":"linux-tls-fake","platform":"linux","strategy":"split","status":"SKIP","evidence":null,"reason":"pending"},`, 1), "duplicate case id"},
		{"empty report", `{"format":"desync.blockcheck/v1","reference":{"zapret_revision":"` + BlockcheckZapretRevision + `","flowseal_revision":"` + BlockcheckFlowsealRevision + `"},"cases":[]}`, "no cases"},
		{"trailing document", validBlockcheckJSON("PASS", validEvidence, "") + `{}`, "exactly one JSON document"},
		{"empty input", "", "empty report"},
		{"truncated json", `{"format":`, "decode report"},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateBlockcheckReport([]byte(test.input))
			if err == nil {
				t.Fatalf("expected an error containing %q", test.reason)
			}
			if !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("error %q does not contain %q", err, test.reason)
			}
		})
	}
}

func TestNormalizeBlockcheckReportDeterministic(t *testing.T) {
	t.Parallel()
	input := `{"format":"desync.blockcheck/v1",` +
		`"reference":{"zapret_revision":"` + BlockcheckZapretRevision + `","flowseal_revision":"` + BlockcheckFlowsealRevision + `"},` +
		`"cases":[` +
		`{"id":"z-last","platform":"windows","strategy":"multisplit","status":"SKIP","evidence":null,"reason":"pending VM"},` +
		`{"id":"a-first","platform":"linux","strategy":"fake","status":"PASS","evidence":` + validEvidence + `,"reason":""},` +
		`{"id":"m-mid","platform":"linux","strategy":"fake","status":"FAIL","evidence":null,"reason":"timeout"}` +
		`]}`
	normalized, report, err := NormalizeBlockcheckReportData([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 3 {
		t.Fatalf("unexpected report %+v", report)
	}
	text := string(normalized)
	if !strings.HasSuffix(text, "\n") {
		t.Fatal("normalized report must end with a newline")
	}
	first := strings.Index(text, `"a-first"`)
	second := strings.Index(text, `"m-mid"`)
	third := strings.Index(text, `"z-last"`)
	if first < 0 || second < 0 || third < 0 || !(first < second && second < third) {
		t.Fatalf("cases are not sorted by platform and id: %s", text)
	}
	again, _, err := NormalizeBlockcheckReportData(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != text {
		t.Fatal("normalization is not idempotent")
	}
	// Every case object keeps the exact six documented keys.
	if strings.Count(text, `"evidence"`) != 3 {
		t.Fatalf("evidence key must always be present: %s", text)
	}
}

func TestBlockcheckFixture(t *testing.T) {
	t.Parallel()
	// The fixture is a parser test input, not an executed blockcheck run.
	data := readTestData(t, "testdata/blockcheck/parser-input-synthetic.json")
	normalized, report, err := NormalizeBlockcheckReportData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 3 {
		t.Fatalf("unexpected fixture %+v", report)
	}
	if len(normalized) == 0 {
		t.Fatal("empty normalized fixture")
	}
}

func TestBlockcheckTemplateValidates(t *testing.T) {
	t.Parallel()
	// The shipped template must stay valid: every case is an honest SKIP
	// because no disposable VM run has produced evidence yet.
	data := readTestData(t, "../../../docs/examples/desync-tools/blockcheck-report-template.json")
	_, report, err := NormalizeBlockcheckReportData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) == 0 {
		t.Fatal("template has no cases")
	}
	for _, blockcheckCase := range report.Cases {
		if blockcheckCase.Status != BlockcheckSkip {
			t.Fatalf("template case %s must stay SKIP until a run is executed", blockcheckCase.ID)
		}
		if blockcheckCase.Evidence != nil {
			t.Fatalf("template case %s must not carry evidence", blockcheckCase.ID)
		}
	}
}
