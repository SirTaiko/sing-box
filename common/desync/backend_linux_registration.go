//go:build linux

package desync

// Fixed persistent-anchor identity: schema, canonical userdata grammar and the
// strict reader of the marker-chain records.
//
// The selected-A contract fixes these names and this grammar; they are not
// implementation choices. Every record is ASCII without spaces, trailing NUL or
// optional fields, so a malformed or foreign record is a visible collision
// instead of a silently reinterpreted identity. The writer rejects malformed or
// oversize userdata rather than truncating it, and the reader rejects anything
// the writer could not have produced.
//
// The anchor objects themselves belong to the existing network namespace and
// outlive every Lease, Engine and process: nothing here deletes, disables,
// replaces or dormants them.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// anchorUserdataVersion is the fixed schema version of every record.
	anchorUserdataVersion = "sbds:1"

	// anchorTableName is the fixed table name in both families.
	anchorTableName = "sb_desync"
	// anchorMarkerChainName is the fixed unreferenced marker chain.
	anchorMarkerChainName = "__sbds_v1"
	// anchorBaseInputName and anchorBaseOutputName are the fixed base chains.
	anchorBaseInputName  = "input"
	anchorBaseOutputName = "output"
	// anchorBaseHookPriority is the fixed base-chain priority.
	anchorBaseHookPriority = -150
	// anchorTagInitial is the first irreversible per-family injection tag.
	anchorTagInitial = uint32(0x53590001)
	// anchorUserdataMax is NFT_USERDATA_MAXLEN. A longer record is rejected.
	anchorUserdataMax = 256
	// anchorChainPrefix marks the per-capture regular chains.
	anchorChainPrefix = "c_"
)

// anchorRecordKind is the leading record type of one marker-chain userdata.
type anchorRecordKind byte

const (
	anchorKindAnchor   anchorRecordKind = 'a'
	anchorKindBase     anchorRecordKind = 'b'
	anchorKindCapture  anchorRecordKind = 'c'
	anchorKindManifest anchorRecordKind = 'm'
	anchorKindTag      anchorRecordKind = 't'
	anchorKindPort     anchorRecordKind = 'p'
)

// anchorCaptureRoles are the fixed per-capture rule roles.
var anchorCaptureRoles = map[string]bool{
	"chain-o": true, "chain-i": true, "chain-e": true,
	"entry-o": true, "entry-i": true, "entry-e": true,
	"inject": true, "queue-o": true, "queue-i": true, "queue-e": true,
}

// anchorIdentity is the validated identity of one family's fixed anchors.
type anchorIdentity struct {
	family string
	epoch  string
	// nextTag is the next unallocated injection tag of this family. Tags are
	// allocated monotonically and never recycled during the namespace
	// lifetime; the first value beyond uint32 is the exhausted sentinel, so
	// the counter itself is a uint64.
	nextTag uint64
	// anchorHandle and tagHandle are the exact marker-chain rule handles.
	anchorHandle uint64
	tagHandle    uint64
}

// newAnchorEpoch returns one independently generated 128-bit epoch token in the
// canonical lowercase 32-hex encoding.
func newAnchorEpoch() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("desync: generate anchor epoch: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// newAnchorNonce returns one independently generated 128-bit identity token.
func newAnchorNonce() (string, error) { return newAnchorEpoch() }

// anchorFamilyName maps the capture family to the fixed userdata token.
func anchorFamilyName(family Family) (string, error) {
	switch family {
	case FamilyIPv4:
		return "ip", nil
	case FamilyIPv6:
		return "ip6", nil
	default:
		return "", fmt.Errorf("desync: unsupported anchor family %d", family)
	}
}

// anchorMarkerUserdata builds the anchor marker record.
func anchorMarkerUserdata(family, epoch string) string {
	return anchorUserdataVersion + ":a:" + family + ":" + epoch
}

// anchorBaseUserdata builds one base-chain identity record.
func anchorBaseUserdata(epoch, base string) string {
	return anchorUserdataVersion + ":b:" + epoch + ":" + base
}

// anchorTagUserdata builds the irreversible tag high-water record. The counter
// may name the exhausted sentinel 2^32, which no capture can allocate.
func anchorTagUserdata(epoch string, nextTag uint64) string {
	return anchorUserdataVersion + ":t:" + epoch + ":" + strconv.FormatUint(nextTag, 10)
}

// anchorCaptureUserdata builds one capture-owned record.
func anchorCaptureUserdata(epoch, process, capture, role string) string {
	return anchorUserdataVersion + ":c:" + epoch + ":" + process + ":" + capture + ":" + role
}

// anchorManifestUserdata builds the capture manifest record. The optional ICMP
// queue is an explicit "-", never a zero sentinel: queue0 is a valid queue.
func anchorManifestUserdata(epoch, process, capture string, ports anchorQueuePorts) string {
	icmp := "-"
	if ports.icmpSet {
		icmp = strconv.Itoa(int(ports.icmp))
	}
	return anchorUserdataVersion + ":m:" + epoch + ":" + process + ":" + capture + ":" +
		strconv.Itoa(int(ports.out)) + ":" + strconv.Itoa(int(ports.in)) + ":" + icmp + ":" +
		strconv.FormatUint(ports.pidnsDev, 10) + ":" + strconv.FormatUint(ports.pidnsIno, 10) + ":" +
		strconv.FormatUint(ports.tgid, 10) + ":" + strconv.FormatUint(ports.startTicks, 10)
}

// anchorQueuePorts is the manifest's queue/owner tuple.
type anchorQueuePorts struct {
	out, in  uint16
	icmp     uint16
	icmpSet  bool
	pidnsDev uint64
	pidnsIno uint64
	tgid     uint64
	// startTicks is the recorded incarnation start time.
	startTicks uint64
}

// anchorPortUserdata builds one transient port record. phase is "o" (socket may
// be opening, not share-published) or "w" (outq bound and durably witnessed).
// The recorded port is the netlink port id of the capture's queue socket: a
// nonzero uint32 with the queue-class high bit set. It is not a qnum (qnums are
// uint16 and live in the manifest record).
func anchorPortUserdata(epoch, process, capture string, port uint32, phase string, tag uint32) (string, error) {
	if phase != "o" && phase != "w" {
		return "", fmt.Errorf("desync: invalid port-record phase %q", phase)
	}
	if port == 0 || port&nftQueuePortBit == 0 {
		return "", fmt.Errorf("desync: port record %#x is not a queue-class port", port)
	}
	return anchorUserdataVersion + ":p:" + epoch + ":" + process + ":" + capture + ":" +
		strconv.FormatUint(uint64(port), 10) + ":" + phase + ":" + strconv.FormatUint(uint64(tag), 10), nil
}

// anchorRecord is one parsed marker-chain userdata.
type anchorRecord struct {
	kind     anchorRecordKind
	family   string
	epoch    string
	process  string
	capture  string
	base     string
	role     string
	port     uint32
	phase    string
	tag      uint64
	ports    anchorQueuePorts
	rawValue string
}

// validateAnchorUserdata rejects records the writer could not have produced:
// wrong version, unknown kind, wrong field count, non-canonical numbers,
// non-lowercase-hex tokens, oversize values and embedded NUL/space.
func validateAnchorUserdata(value string) error {
	if len(value) == 0 {
		return errors.New("desync: empty anchor userdata")
	}
	if len(value) > anchorUserdataMax {
		return fmt.Errorf("desync: anchor userdata of %d bytes exceeds %d", len(value), anchorUserdataMax)
	}
	if strings.IndexByte(value, 0) >= 0 || strings.IndexByte(value, ' ') >= 0 {
		return errors.New("desync: anchor userdata contains a forbidden byte")
	}
	_, err := parseAnchorUserdata(value)
	return err
}

// parseAnchorUserdata parses and validates one marker-chain record.
func parseAnchorUserdata(value string) (anchorRecord, error) {
	record := anchorRecord{rawValue: value}
	if len(value) == 0 || len(value) > anchorUserdataMax {
		return record, fmt.Errorf("desync: invalid anchor userdata length %d", len(value))
	}
	if strings.IndexByte(value, 0) >= 0 || strings.IndexByte(value, ' ') >= 0 {
		return record, errors.New("desync: anchor userdata contains a forbidden byte")
	}
	fields := strings.Split(value, ":")
	if len(fields) < 3 || fields[0] != "sbds" || fields[1] != "1" {
		return record, fmt.Errorf("desync: unknown anchor schema %q", value)
	}
	if len(fields[2]) != 1 {
		return record, fmt.Errorf("desync: unknown anchor record kind %q", fields[2])
	}
	record.kind = anchorRecordKind(fields[2][0])
	switch record.kind {
	case anchorKindAnchor:
		if len(fields) != 5 {
			return record, fmt.Errorf("desync: anchor record has %d fields", len(fields))
		}
		if fields[3] != "ip" && fields[3] != "ip6" {
			return record, fmt.Errorf("desync: unknown anchor family %q", fields[3])
		}
		if err := validateAnchorToken(fields[4]); err != nil {
			return record, err
		}
		record.family, record.epoch = fields[3], fields[4]
	case anchorKindBase:
		if len(fields) != 5 {
			return record, fmt.Errorf("desync: base record has %d fields", len(fields))
		}
		if err := validateAnchorToken(fields[3]); err != nil {
			return record, err
		}
		if fields[4] != anchorBaseInputName && fields[4] != anchorBaseOutputName {
			return record, fmt.Errorf("desync: unknown base chain %q", fields[4])
		}
		record.epoch, record.base = fields[3], fields[4]
	case anchorKindCapture:
		if len(fields) != 7 {
			return record, fmt.Errorf("desync: capture record has %d fields", len(fields))
		}
		for _, token := range fields[3:6] {
			if err := validateAnchorToken(token); err != nil {
				return record, err
			}
		}
		if !anchorCaptureRoles[fields[6]] {
			return record, fmt.Errorf("desync: unknown capture role %q", fields[6])
		}
		record.epoch, record.process, record.capture, record.role = fields[3], fields[4], fields[5], fields[6]
	case anchorKindManifest:
		if len(fields) != 13 {
			return record, fmt.Errorf("desync: manifest record has %d fields", len(fields))
		}
		if err := validateAnchorToken(fields[3]); err != nil {
			return record, err
		}
		if err := validateAnchorToken(fields[4]); err != nil {
			return record, err
		}
		if err := validateAnchorToken(fields[5]); err != nil {
			return record, err
		}
		out, err := anchorCanonicalUint(fields[6], 65535)
		if err != nil {
			return record, err
		}
		in, err := anchorCanonicalUint(fields[7], 65535)
		if err != nil {
			return record, err
		}
		record.ports.out, record.ports.in = uint16(out), uint16(in)
		if fields[8] != "-" {
			icmp, icmpErr := anchorCanonicalUint(fields[8], 65535)
			if icmpErr != nil {
				return record, icmpErr
			}
			record.ports.icmp, record.ports.icmpSet = uint16(icmp), true
		}
		for index, target := range []*uint64{&record.ports.pidnsDev, &record.ports.pidnsIno,
			&record.ports.tgid, &record.ports.startTicks} {
			parsed, parseErr := anchorCanonicalUint(fields[9+index], ^uint64(0))
			if parseErr != nil {
				return record, parseErr
			}
			*target = parsed
		}
		record.epoch, record.process, record.capture = fields[3], fields[4], fields[5]
	case anchorKindTag:
		if len(fields) != 5 {
			return record, fmt.Errorf("desync: tag record has %d fields", len(fields))
		}
		if err := validateAnchorToken(fields[3]); err != nil {
			return record, err
		}
		tag, err := anchorCanonicalUint(fields[4], uint64(^uint32(0))+1)
		if err != nil {
			return record, err
		}
		if tag < uint64(anchorTagInitial) {
			return record, fmt.Errorf("desync: tag record %q is below the initial tag", fields[4])
		}
		record.epoch, record.tag = fields[3], tag
	case anchorKindPort:
		if len(fields) != 9 {
			return record, fmt.Errorf("desync: port record has %d fields", len(fields))
		}
		for _, token := range fields[3:6] {
			if err := validateAnchorToken(token); err != nil {
				return record, err
			}
		}
		port, err := anchorCanonicalUint(fields[6], uint64(^uint32(0)))
		if err != nil {
			return record, err
		}
		if uint32(port)&nftQueuePortBit == 0 || port == 0 {
			return record, fmt.Errorf("desync: port record %q is not a queue-class port", fields[6])
		}
		if fields[7] != "o" && fields[7] != "w" {
			return record, fmt.Errorf("desync: invalid port-record phase %q", fields[7])
		}
		tag, err := anchorCanonicalUint(fields[8], uint64(^uint32(0)))
		if err != nil {
			return record, err
		}
		record.epoch, record.process, record.capture = fields[3], fields[4], fields[5]
		record.port, record.phase, record.tag = uint32(port), fields[7], tag
	default:
		return record, fmt.Errorf("desync: unknown anchor record kind %q", fields[2])
	}
	return record, nil
}

// validateAnchorToken checks one lowercase 32-hex identity token.
func validateAnchorToken(token string) error {
	if len(token) != 32 {
		return fmt.Errorf("desync: identity token %q is not 32 hex characters", token)
	}
	for _, value := range token {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return fmt.Errorf("desync: identity token %q is not lowercase hex", token)
		}
	}
	return nil
}

// anchorCanonicalUint parses an unsigned decimal with no leading zero (except
// "0") inside the inclusive bound.
func anchorCanonicalUint(value string, maximum uint64) (uint64, error) {
	if value == "" {
		return 0, errors.New("desync: empty numeric field")
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, fmt.Errorf("desync: non-canonical numeric field %q", value)
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("desync: numeric field %q is not decimal", value)
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("desync: numeric field %q: %w", value, err)
	}
	if parsed > maximum {
		return 0, fmt.Errorf("desync: numeric field %q exceeds %d", value, maximum)
	}
	return parsed, nil
}
