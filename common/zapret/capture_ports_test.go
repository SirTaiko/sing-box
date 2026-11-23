package zapret

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecipeCapturePorts(t *testing.T) {
	zero := capturePortRange{0, 0}
	for _, tc := range []struct {
		name     string
		tokens   []string
		tcp, udp []capturePortRange
	}{
		{"unmarked", []string{"--filter-tcp=80"}, nil, nil},
		{"every section and repeated filters", []string{profilePortCapture, "--filter-tcp=81,443", "--filter-tcp=80-82", "--new", "--filter-udp=443,8443"}, []capturePortRange{zero, {80, 82}, {443, 443}}, []capturePortRange{zero, {443, 443}, {8443, 8443}}},
		{"absent UDP", []string{profilePortCapture, "--filter-tcp=80"}, []capturePortRange{zero, {80, 80}}, []capturePortRange{zero}},
		{"UDP wildcard", []string{profilePortCapture, "--filter-udp=*", "--new", "--filter-tcp=443"}, []capturePortRange{zero, {443, 443}}, nil},
		{"negative TCP", []string{profilePortCapture, "--filter-tcp=80", "--new", "--filter-tcp=~443", "--filter-udp=5001"}, nil, []capturePortRange{zero, {5001, 5001}}},
		{"implicit wildcard section", []string{profilePortCapture, "--filter-tcp=443", "--new", "--filter-l7=tls"}, nil, nil},
		{"unfiltered first section", []string{profilePortCapture, "--comment=ordinary", "--new", "--filter-tcp=80"}, nil, nil},
		{"import", []string{profilePortCapture, "--import=other", "--filter-tcp=443"}, nil, nil},
		{"future option", []string{profilePortCapture, "--filter-tcp=443", "--future=x"}, nil, nil},
		{"invalid range", []string{profilePortCapture, "--filter-tcp=81-80"}, nil, nil},
		{"bounded complexity", []string{profilePortCapture, "--filter-tcp=2,4,6,8,10,12,14,16"}, nil, []capturePortRange{zero}},
		{"games", []string{profilePortCapture, "--filter-tcp=80,443,2053,8443", "--new", "--filter-tcp=1024-65535", "--new", "--filter-udp=443,1024-65535"}, []capturePortRange{zero, {80, 80}, {443, 443}, {1024, 65535}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := recipeCapturePorts(tc.tokens)
			if !reflect.DeepEqual(scope.tcp, tc.tcp) || !reflect.DeepEqual(scope.udp, tc.udp) {
				t.Fatalf("got %+v; want TCP %v UDP %v", scope, tc.tcp, tc.udp)
			}
		})
	}
}

func TestPacketDiagnosticsKeepOriginalCapture(t *testing.T) {
	t.Setenv("MVPN_ZAPRET_DEBUG", "1")
	p := &profile{tokens: []string{profilePortCapture, "--filter-tcp=80"}}
	if got := p.capturePorts(); got.tcp != nil || got.udp != nil {
		t.Fatal("diagnostics narrowed capture")
	}
}

func TestBundledCapturePorts(t *testing.T) {
	root := os.Getenv("MVPN_TEST_ZAPRET_BUNDLE")
	if root == "" {
		t.Skip("requires the client bundle")
	}
	dir := filepath.Join(root, "strategy")
	wantTCP := []capturePortRange{{0, 0}, {80, 80}, {443, 443}, {1024, 65535}}
	for _, name := range []string{"alt11-games-any.conf.json", "fake-tls-auto-games.conf.json", "simple-fake-games.conf.json"} {
		t.Run(name, func(t *testing.T) {
			tokens, err := loadStrategy(filepath.Join(dir, name), dir)
			if err != nil {
				t.Fatal(err)
			}
			scope := recipeCapturePorts(tokens)
			if !reflect.DeepEqual(scope.tcp, wantTCP) || scope.udp != nil {
				t.Fatalf("unexpected bundled scope: %+v", scope)
			}
		})
	}
}
