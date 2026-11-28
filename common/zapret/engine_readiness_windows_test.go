package zapret

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWindowsReadinessIsExactAndRunsOnce(t *testing.T) {
	for _, captureFirst := range []bool{false, true} {
		engine, err := newPlatformEngine(platformOptions{profile: &profile{tokens: []string{"--filter-tcp=80"}}})
		if err != nil {
			t.Fatal(err)
		}
		e := engine.(*windowsEngine)
		args := e.arguments()
		if !slices.Contains(args, "--filter-tcp=80") {
			t.Fatal("profile lost")
		}
		for _, text := range []string{args[len(args)-1], "LUA INIT DONE", "log " + captureReadinessMarker} {
			e.handleLine(text)
		}
		first, last := captureReadinessMarker, "LUA: "+e.readyToken
		if !captureFirst {
			first, last = last, first
		}
		e.handleLine(first)
		select {
		case <-e.readyCh:
			t.Fatal("premature readiness")
		default:
		}
		e.handleLine(last)
		select {
		case <-e.readyCh:
		default:
			t.Fatal("missing readiness")
		}
		e.handleLine(last)
		e.handleLine("later diagnostic")
	}
}

func TestStockWindowsCaptureFailureDoesNotReportReady(t *testing.T) {
	exe := os.Getenv("MVPN_TEST_ZAPRET_ENGINE")
	if exe == "" {
		t.Skip("requires the stock Windows engine")
	}
	engine, _ := newPlatformEngine(platformOptions{profile: &profile{}, logger: new(stockLogger), tag: "test"})
	e := engine.(*windowsEngine)
	e.filter = "mvpn_invalid_filter"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, e.arguments()...)
	flush := attachEngineOutput(cmd, e.options, e.handleLine)
	err := cmd.Run()
	flush()
	if err == nil || ctx.Err() != nil {
		t.Fatal("invalid WinDivert filter did not fail promptly")
	}
	if e.ready || !strings.Contains(strings.ToLower(e.outputTail()), "filter") {
		t.Fatal("expected a capture-filter diagnostic and no ready signal")
	}
}
