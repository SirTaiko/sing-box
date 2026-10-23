package option

import (
	"testing"

	sjson "github.com/sagernet/sing/common/json"
)

func TestDirectDesyncStreamRuleDecode(t *testing.T) {
	content := `{
		"name": "stream-http",
		"network": ["tcp"],
		"ip_version": [4, 6],
		"port": [80, 443],
		"port_range": ["8000-9000"],
		"port_exclude": [8443],
		"protocol": ["http", "tls"],
		"domain": ["example.com"],
		"domain_exclude": ["skip.example.com"],
		"ip_cidr": ["10.0.0.0/8"],
		"ip_cidr_exclude": ["10.1.0.0/16"],
		"methods": ["http_tamper", "tls_record", "split"],
		"http_tamper": {
			"hostcase": true,
			"hostspell": "HoSt",
			"hostdot": true,
			"domcase": true,
			"methodspace": true,
			"methodeol": true,
			"unixeol": true,
			"hostpad": 64
		},
		"tls_record": {"pos": "sniext"},
		"split": {
			"split_pos": ["1", "-2", "host+3", "midsld"],
			"split_http_req": "method",
			"split_tls": "sni",
			"disorder": "any",
			"oob": "tls",
			"oob_data": "0x1b",
			"split_any_protocol": true
		},
		"start": "n2",
		"cutoff": "100",
		"mss": 1200,
		"skip_nodelay": false,
		"fix_seg": 10
	}`
	var rule DirectDesyncStreamRule
	if err := sjson.Unmarshal([]byte(content), &rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Name != "stream-http" || len(rule.Methods) != 3 {
		t.Fatalf("rule = %+v", rule)
	}
	if len(rule.Port) != 2 || rule.Port[1] != 443 || len(rule.PortRange) != 1 {
		t.Fatalf("match fields = %+v", rule.DirectDesyncStreamMatch)
	}
	if rule.HTTPTamper == nil || !rule.HTTPTamper.HostCase || rule.HTTPTamper.HostSpell != "HoSt" ||
		rule.HTTPTamper.HostPad != 64 || !rule.HTTPTamper.UnixEOL {
		t.Fatalf("http_tamper = %+v", rule.HTTPTamper)
	}
	if rule.TLSRecord == nil || rule.TLSRecord.Pos != "sniext" {
		t.Fatalf("tls_record = %+v", rule.TLSRecord)
	}
	if rule.Split == nil || rule.Split.Disorder != "any" || rule.Split.OOB != "tls" ||
		rule.Split.SplitAnyProtocol != true || len(rule.Split.SplitPos) != 4 {
		t.Fatalf("split = %+v", rule.Split)
	}
	if rule.Split.OOBData == nil || rule.Split.OOBData.Value != 0x1b {
		t.Fatalf("oob_data = %+v", rule.Split.OOBData)
	}
	if rule.FixSeg == nil || rule.FixSeg.Default || rule.FixSeg.Milliseconds != 10 {
		t.Fatalf("fix_seg = %v", rule.FixSeg)
	}
	if rule.Start != "n2" || rule.Cutoff != "100" || rule.MSS != 1200 {
		t.Fatalf("rule metadata = %+v", rule)
	}
	addRule := func(content string) (DirectDesyncStreamRule, error) {
		var rule DirectDesyncStreamRule
		err := sjson.Unmarshal([]byte(content), &rule)
		return rule, err
	}
	defaultRule, err := addRule(`{"fix_seg": true}`)
	if err != nil || defaultRule.FixSeg == nil || !defaultRule.FixSeg.Default || defaultRule.FixSeg.Milliseconds != 0 {
		t.Fatalf("fix_seg=true = %+v %v", defaultRule.FixSeg, err)
	}
	zeroRule, err := addRule(`{"fix_seg": 0}`)
	if err != nil || zeroRule.FixSeg == nil || zeroRule.FixSeg.Default || zeroRule.FixSeg.Milliseconds != 0 {
		t.Fatalf("fix_seg=0 = %+v %v", zeroRule.FixSeg, err)
	}
	valueRule, err := addRule(`{"fix_seg": 250}`)
	if err != nil || valueRule.FixSeg == nil || valueRule.FixSeg.Default || valueRule.FixSeg.Milliseconds != 250 {
		t.Fatalf("fix_seg=250 = %+v %v", valueRule.FixSeg, err)
	}
	nullRule, err := addRule(`{"fix_seg": null}`)
	if err != nil || nullRule.FixSeg != nil {
		t.Fatalf("fix_seg=null must mean absent: %+v %v", nullRule.FixSeg, err)
	}
	for _, content := range []string{`{"fix_seg": false}`, `{"fix_seg": "10"}`, `{"fix_seg": {}}`} {
		if _, err = addRule(content); err == nil {
			t.Fatalf("decode %s must fail", content)
		}
	}
}

func TestDirectDesyncOOBByteDecode(t *testing.T) {
	tests := map[string]byte{
		`"a"`:    0x61,
		`"0x1b"`: 0x1b,
		`"0XFF"`: 0xff,
		`"\t"`:   '\t',
	}
	for content, want := range tests {
		var value DirectDesyncOOBByte
		if err := sjson.Unmarshal([]byte(content), &value); err != nil {
			t.Fatalf("decode %s: %v", content, err)
		}
		if value.Value != want {
			t.Fatalf("decode %s = %#x, want %#x", content, value.Value, want)
		}
	}
	for _, content := range []string{`""`, `"ab"`, `"0xzz"`, `"0x1"`, `1`} {
		var value DirectDesyncOOBByte
		if err := sjson.Unmarshal([]byte(content), &value); err == nil {
			t.Fatalf("decode %s must fail", content)
		}
	}
}

func TestDirectDesyncStreamMatchIndependentOfPacketActions(t *testing.T) {
	// The stream match object deliberately has no packet action fields.
	content := `{"name":"x","methods":["split"],"split":{"split_pos":["1"]},"rules":[],"fake":{"payloads":[]}}`
	var rule DirectDesyncStreamRule
	if err := sjson.Unmarshal([]byte(content), &rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Name != "x" {
		t.Fatalf("rule = %+v", rule)
	}
}
