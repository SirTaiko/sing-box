package desync

import (
	"strings"
	"testing"
)

// TestComApartmentEnterBalancesOnlyAcquiredReferences pins the COM
// initialization reference accounting of one query: S_OK and S_FALSE each
// acquire one reference that this invocation must balance exactly once, while
// RPC_E_CHANGED_MODE and any other failure acquire nothing and must never
// decrement another owner's apartment.
func TestComApartmentEnterBalancesOnlyAcquiredReferences(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		result             uint32
		wantRelease        bool
		wantUninitialize   int
		wantErrorSubstring string
	}{
		{name: "S_OK", result: comSOK, wantRelease: true, wantUninitialize: 1},
		{name: "S_FALSE", result: comSFalse, wantRelease: true, wantUninitialize: 1},
		{name: "RPC_E_CHANGED_MODE", result: comRPCChangedMode, wantRelease: false, wantUninitialize: 0},
		{name: "E_FAIL", result: 0x80004005, wantRelease: false, wantUninitialize: 0, wantErrorSubstring: "CoInitializeEx failed: 0x80004005"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			uninitialized := 0
			release, err := comApartmentEnter(testCase.result, func() { uninitialized++ })
			if testCase.wantErrorSubstring != "" {
				if err == nil {
					t.Fatal("failure HRESULT must return an error")
				}
				if !strings.Contains(err.Error(), testCase.wantErrorSubstring) {
					t.Fatalf("unexpected error text: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if testCase.wantRelease {
				if release == nil {
					t.Fatal("acquired initialization reference must return a release")
				}
				release()
			} else if release != nil {
				t.Fatal("a call that acquired no reference must not return a release")
			}
			if uninitialized != testCase.wantUninitialize {
				t.Fatalf("CoUninitialize calls = %d, want %d", uninitialized, testCase.wantUninitialize)
			}
		})
	}
}
