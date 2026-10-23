package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
)

type bindWaitTestSource struct {
	interfaces []control.Interface
}

func (s bindWaitTestSource) Interfaces() []control.Interface {
	return s.interfaces
}

type bindWaitTestClock struct {
	now time.Time
}

func (c *bindWaitTestClock) Now() time.Time {
	return c.now
}

func (c *bindWaitTestClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(duration)
	return nil
}

func bindWaitTestInterfaces(t *testing.T) []control.Interface {
	t.Helper()
	parsePrefix := func(value string) netip.Prefix {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatal(err)
		}
		return prefix
	}
	return []control.Interface{{
		Name:      "eth0",
		Index:     1,
		Flags:     net.FlagUp,
		Addresses: []netip.Prefix{parsePrefix("fd00::1/8"), parsePrefix("2001:db8::1/64")},
	}}
}

func TestToolsDesyncBindWaitOutput(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "bindings.json")
	document := `{"bindings":[{"interface":"eth0","ip_version":6,"link_local":"unwanted"}]}`
	if err := os.WriteFile(inputPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	command := newToolsDesyncBindWaitCommand(
		bindWaitTestSource{interfaces: bindWaitTestInterfaces(t)},
		&bindWaitTestClock{now: time.Unix(100, 0)},
	)
	stdout, stderr, err := executeDesyncCommand(t, command, nil, "--input", inputPath)
	if err != nil {
		t.Fatalf("bind-wait failed: %v (stderr %s)", err, stderr)
	}
	var output bindWaitOutput
	if err = json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output is not JSON: %v: %q", err, stdout)
	}
	if len(output.Bindings) != 1 {
		t.Fatalf("unexpected output %+v", output)
	}
	endpoint := output.Bindings[0]
	if endpoint.Address != "fd00::1" || endpoint.Interface != "eth0" || endpoint.IPVersion != 6 {
		t.Fatalf("unexpected endpoint %+v", endpoint)
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatal("output must end with a newline")
	}
}

func TestToolsDesyncBindWaitStdinAndZone(t *testing.T) {
	document := `{"bindings":[{"address":"fe80::1","interface":"eth0","ip_version":6}]}`
	command := newToolsDesyncBindWaitCommand(
		bindWaitTestSource{interfaces: bindWaitTestInterfaces(t)},
		&bindWaitTestClock{now: time.Unix(100, 0)},
	)
	stdout, _, err := executeDesyncCommand(t, command, []byte(document), "--input", "-")
	if err != nil {
		t.Fatal(err)
	}
	var output bindWaitOutput
	if err = json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if output.Bindings[0].Address != "fe80::1%eth0" {
		t.Fatalf("zone missing from the resolved endpoint: %+v", output.Bindings[0])
	}
}

func TestToolsDesyncBindWaitStrictInput(t *testing.T) {
	directory := t.TempDir()
	cases := []string{
		// Unknown top-level field.
		`{"bindings":[{"address":"192.0.2.1","ip_version":4}],"listen":true}`,
		// Unknown binding leaf.
		`{"bindings":[{"address":"192.0.2.1","ip_version":4,"wait_route":"1s"}]}`,
		// Empty list: the wait-only command needs at least one condition.
		`{"bindings":[]}`,
		// Invalid schema.
		`{"bindings":[{"interface":"eth0"}]}`,
		`{"bindings":[]}`,
	}
	for index, document := range cases {
		inputPath := filepath.Join(directory, "case.json")
		if err := os.WriteFile(inputPath, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		command := newToolsDesyncBindWaitCommand(
			bindWaitTestSource{interfaces: bindWaitTestInterfaces(t)},
			&bindWaitTestClock{now: time.Unix(100, 0)},
		)
		if _, _, err := executeDesyncCommand(t, command, nil, "--input", inputPath); err == nil {
			t.Fatalf("case %d: expected a strict input error for %s", index, document)
		}
	}
	command := newToolsDesyncBindWaitCommand(nil, nil)
	if _, _, err := executeDesyncCommand(t, command, nil); err == nil {
		t.Fatal("expected a missing --input error")
	}
}
