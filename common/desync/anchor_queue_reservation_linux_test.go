//go:build linux

package desync

import (
	"fmt"
	"reflect"
	"testing"
)

// MODEL: the competing manifest is published, but its qnums are not yet
// kernel-bound. Exercise the actual both-family snapshot -> allocation caller.
func TestSource37ExplicitManifestReservation(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, role := range []string{"out", "in", "icmp"} {
			t.Run(fmt.Sprintf("family-%d/%s", family, role), func(t *testing.T) {
				seams := installLinuxCaptureSeams(t, nil)
				session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000034}
				for _, f := range []Family{FamilyIPv4, FamilyIPv6} {
					if err := ensureAnchorFamily(session, f, true); err != nil {
						t.Fatal(err)
					}
				}
				state, err := readAnchorFamilyState(session, family)
				if err != nil {
					t.Fatal(err)
				}
				process, capture := "11111111111111111111111111111111", "22222222222222222222222222222222"
				ports := anchorQueuePorts{out: 16610, in: 16611, icmp: 16612, icmpSet: true, pidnsDev: 1, pidnsIno: 2, tgid: 4242, startTicks: 99}
				m, err := nftRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, nil, []byte(anchorManifestUserdata(state.epoch, process, capture, ports)))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := session.batch([]nftRequest{m}); err != nil {
					t.Fatal(err)
				}
				guard, err := seams.bindGuard(anchorGuardAddress(process))
				if err != nil {
					t.Fatal(err)
				}
				defer guard.close()
				observeOwnerProcess = func(anchorRecord) (anchorOwnerObservation, error) {
					return anchorOwnerObservation{verdict: anchorOwnerLive, reason: "MODEL live peer"}, nil
				}
				before := modelCaptureRecords(t, seams, family)
				q := ports.out
				if role == "in" {
					q = ports.in
				}
				if role == "icmp" {
					q = ports.icmp
				}
				_, lease := newLinuxCaptureLease(t, int(q))
				err = lease.StartCapture()
				if err == nil {
					_ = lease.Close(nil)
					t.Fatal("MODEL F-02: explicit qnum stole another manifest reservation")
				}
				if !contains(err.Error(), "reserved") {
					t.Fatalf("MODEL: refusal was not manifest exclusion: %v", err)
				}
				if qnumLive(int(q)) || len(seams.boundPortList()) != 0 || len(seams.kernel.eventList()) != 0 {
					t.Fatal("MODEL F-02: reserved conflict reached local reservation/transport/BIND")
				}
				if !reflect.DeepEqual(before, modelCaptureRecords(t, seams, family)) {
					t.Fatal("MODEL: competing manifest mutated")
				}
				if err := lease.Close(nil); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
