package desync

import (
	"fmt"
	"strings"
)

// Stage is the upstream nfqws stage slot of a desync method.
//
// Upstream (`nfq/desync.c` `desync_valid_zero_stage` /
// `desync_valid_first_stage` / `desync_valid_second_stage_*`) models a rule as
// `<mode0>,<mode>[,<mode2>]`:
//
//	mode0 (zero stage)   runs on the SYN segment only (synack, syndata)
//	mode  (first stage)  runs on the first data packet (fake family, rst family,
//	                     IPv6 extension-header family)
//	mode2 (second stage) runs after the first stage (split family, frag, udplen,
//	                     tamper)
//
// A first stage without a second stage is valid; a zero stage requires a first
// stage because upstream's grammar cannot express an empty middle slot. The
// first stage is never "final" (`desync_only_first_stage` returns false), so the
// second stage is always evaluated when present.
type Stage uint8

const (
	StageNone Stage = iota
	StageZero
	StageFirst
	StageSecond
)

func (s Stage) String() string {
	switch s {
	case StageZero:
		return "zero"
	case StageFirst:
		return "first"
	case StageSecond:
		return "second"
	default:
		return "none"
	}
}

// MethodKind is one upstream dpi_desync_mode value. The numeric values are
// private to this package; names and aliases follow `desync_mode_from_string`.
type MethodKind uint8

const (
	MethodNone MethodKind = iota
	MethodSynAck
	MethodSynData
	MethodFake
	MethodFakeKnown
	MethodRST
	MethodRSTACK
	MethodHopByHop
	MethodDestOpt
	MethodIPFrag1
	MethodFakeDSplit
	MethodFakeDDisorder
	MethodMultiSplit
	MethodMultiDisorder
	MethodHostFakeSplit
	MethodIPFrag2
	MethodUDPLen
	MethodTamper
)

type methodInfo struct {
	kind  MethodKind
	stage Stage
	name  string
}

// methodTable is a direct port of `desync_mode_from_string`. Deprecated
// aliases are accepted with their upstream meaning, not as separate methods.
var methodTable = map[string]methodInfo{
	"synack":        {MethodSynAck, StageZero, "synack"},
	"syndata":       {MethodSynData, StageZero, "syndata"},
	"fake":          {MethodFake, StageFirst, "fake"},
	"fakeknown":     {MethodFakeKnown, StageFirst, "fakeknown"},
	"rst":           {MethodRST, StageFirst, "rst"},
	"rstack":        {MethodRSTACK, StageFirst, "rstack"},
	"hopbyhop":      {MethodHopByHop, StageFirst, "hopbyhop"},
	"destopt":       {MethodDestOpt, StageFirst, "destopt"},
	"ipfrag1":       {MethodIPFrag1, StageFirst, "ipfrag1"},
	"fakedsplit":    {MethodFakeDSplit, StageSecond, "fakedsplit"},
	"split":         {MethodFakeDSplit, StageSecond, "fakedsplit"},
	"fakeddisorder": {MethodFakeDDisorder, StageSecond, "fakeddisorder"},
	"disorder":      {MethodFakeDDisorder, StageSecond, "fakeddisorder"},
	"multisplit":    {MethodMultiSplit, StageSecond, "multisplit"},
	"split2":        {MethodMultiSplit, StageSecond, "multisplit"},
	"multidisorder": {MethodMultiDisorder, StageSecond, "multidisorder"},
	"disorder2":     {MethodMultiDisorder, StageSecond, "multidisorder"},
	"hostfakesplit": {MethodHostFakeSplit, StageSecond, "hostfakesplit"},
	"ipfrag2":       {MethodIPFrag2, StageSecond, "ipfrag2"},
	"udplen":        {MethodUDPLen, StageSecond, "udplen"},
	"tamper":        {MethodTamper, StageSecond, "tamper"},
}

// Method is one compiled stage entry. Name is the canonical upstream name.
type Method struct {
	Kind MethodKind
	Name string
}

func (m Method) Stage() Stage {
	if info, found := methodTable[m.Name]; found {
		return info.stage
	}
	for _, info := range methodTable {
		if info.kind == m.Kind {
			return info.stage
		}
	}
	return StageNone
}

func methodByKind(kind MethodKind) Method {
	for _, info := range methodTable {
		if info.kind == kind {
			return Method{Kind: kind, Name: info.name}
		}
	}
	return Method{Kind: kind}
}

// CompileMethods validates the ordered method list against upstream stage
// grammar and the rule's transports. Unknown names and stage combinations that
// upstream cannot express are rejected rather than accepted as no-ops.
func CompileMethods(names []string, network TransportMask) ([]Method, error) {
	byStage := map[Stage]bool{}
	methods := make([]Method, 0, len(names))
	lastStage := StageNone
	for _, name := range names {
		info, found := methodTable[strings.ToLower(strings.TrimSpace(name))]
		if !found {
			return nil, fmt.Errorf("unknown method %q", name)
		}
		if byStage[info.stage] {
			return nil, fmt.Errorf("duplicate %s stage method %s", info.stage, info.name)
		}
		if info.stage < lastStage {
			return nil, fmt.Errorf("method %s is a %s stage and cannot follow a %s stage method", info.name, info.stage, lastStage)
		}
		byStage[info.stage] = true
		lastStage = info.stage
		methods = append(methods, Method{Kind: info.kind, Name: info.name})
	}
	if byStage[StageZero] && !byStage[StageFirst] {
		return nil, fmt.Errorf("zero stage method requires a first stage method")
	}
	for _, method := range methods {
		if err := validateMethodTransport(method, network); err != nil {
			return nil, err
		}
	}
	return methods, nil
}

func validateMethodTransport(method Method, network TransportMask) error {
	if network == 0 {
		return fmt.Errorf("method %s has no network", method.Name)
	}
	tcp := network&TransportMaskTCP != 0
	udp := network&TransportMaskUDP != 0
	count := 0
	if tcp {
		count++
	}
	if udp {
		count++
	}
	firstTCP := map[MethodKind]bool{
		MethodFake: true, MethodFakeKnown: true, MethodRST: true, MethodRSTACK: true,
		MethodHopByHop: true, MethodDestOpt: true, MethodIPFrag1: true,
	}
	firstUDP := map[MethodKind]bool{
		MethodFake: true, MethodFakeKnown: true,
		MethodHopByHop: true, MethodDestOpt: true, MethodIPFrag1: true,
	}
	secondTCP := map[MethodKind]bool{
		MethodFakeDSplit: true, MethodFakeDDisorder: true, MethodMultiSplit: true,
		MethodMultiDisorder: true, MethodHostFakeSplit: true, MethodIPFrag2: true,
	}
	secondUDP := map[MethodKind]bool{MethodUDPLen: true, MethodTamper: true, MethodIPFrag2: true}
	var applicable []bool
	switch method.Stage() {
	case StageZero:
		applicable = []bool{tcp && !udp}
	case StageFirst:
		if tcp {
			applicable = append(applicable, firstTCP[method.Kind])
		}
		if udp {
			applicable = append(applicable, firstUDP[method.Kind])
		}
	case StageSecond:
		if tcp {
			applicable = append(applicable, secondTCP[method.Kind])
		}
		if udp {
			applicable = append(applicable, secondUDP[method.Kind])
		}
	}
	_ = count
	for _, ok := range applicable {
		if !ok {
			return fmt.Errorf("method %s is not applicable to this rule network", method.Name)
		}
	}
	return nil
}

// stageMethods splits the validated ordered list by stage.
func stageMethods(methods []Method) (zero, first, second *Method) {
	for index := range methods {
		method := &methods[index]
		switch method.Stage() {
		case StageZero:
			zero = method
		case StageFirst:
			first = method
		case StageSecond:
			second = method
		}
	}
	return
}
