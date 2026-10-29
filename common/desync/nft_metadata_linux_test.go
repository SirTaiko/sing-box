//go:build linux

package desync

// Model coverage for the persistent-anchor metadata transport. The transport is
// the contract-mandated substrate for the fixed anchors (chain userdata,
// NLM_F_EXCL creation, full readback and the typed fence receipt) and is wired
// into the capture lifecycle by backend_linux.go. Model tests: no kernel object
// is created, and every case says so. They are model tests: no kernel object is
// created, read or modified.

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nftTestDatagram assembles one netlink datagram from raw messages.
func nftTestDatagram(messages ...[]byte) []byte {
	var out []byte
	for _, message := range messages {
		out = append(out, message...)
	}
	return out
}

// anchorEpochPlaceholder is one canonical 32-hex epoch for the grammar tests.
const anchorEpochPlaceholder = "00112233445566778899aabbccddeeff"

func nftTestMessage(typ uint16, seq uint32, payload []byte) []byte {
	return appendNetlinkMessage(nil, typ, 0, seq, payload)
}

func nftTestError(errno unix.Errno, seq uint32) []byte {
	payload := binary.NativeEndian.AppendUint32(nil, uint32(-int32(errno)))
	payload = append(payload, make([]byte, 16)...)
	return nftTestMessage(unix.NLMSG_ERROR, seq, payload)
}

func TestParseNftDatagramClassifiesReplies(t *testing.T) {
	t.Run("acknowledgement", func(t *testing.T) {
		replies, err := parseNftDatagram(nftTestDatagram(nftTestError(0, 7)))
		if err != nil {
			t.Fatalf("zero acknowledgement: %v", err)
		}
		if len(replies) != 1 || replies[0].typ != unix.NLMSG_ERROR || replies[0].seq != 7 {
			t.Fatalf("replies = %+v", replies)
		}
	})
	t.Run("kernel rejection", func(t *testing.T) {
		_, err := parseNftDatagram(nftTestDatagram(nftTestError(unix.EINVAL, 2)))
		if err == nil {
			t.Fatal("kernel rejection was not an error")
		}
		var kernelErr *nftKernelError
		if !errors.As(err, &kernelErr) {
			t.Fatalf("error type = %T, want *nftKernelError", err)
		}
		if kernelErr.errno != unix.EINVAL || kernelErr.sequence != 2 {
			t.Fatalf("kernel error = %+v", kernelErr)
		}
	})
	t.Run("done and data", func(t *testing.T) {
		data := append(nfgenmsg(2, 0), []byte{0, 0, 0, 0}...)
		replies, err := parseNftDatagram(nftTestDatagram(
			nftTestMessage(uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE, 3, data),
			nftTestMessage(unix.NLMSG_DONE, 4, nil),
		))
		if err != nil {
			t.Fatalf("data datagram: %v", err)
		}
		if len(replies) != 2 || replies[1].typ != unix.NLMSG_DONE {
			t.Fatalf("replies = %+v", replies)
		}
	})
	t.Run("malformed length", func(t *testing.T) {
		datagram := nftTestDatagram(nftTestMessage(unix.NLMSG_DONE, 1, nil))
		binary.NativeEndian.PutUint32(datagram, 100)
		if _, err := parseNftDatagram(datagram); err == nil {
			t.Fatal("a malformed message length was accepted")
		}
	})
	t.Run("truncated error", func(t *testing.T) {
		if _, err := parseNftDatagram(nftTestMessage(unix.NLMSG_ERROR, 1, []byte{0, 0})); err == nil {
			t.Fatal("a truncated error message was accepted")
		}
	})
}

// TestNftRuleMessageRoundTripsUserdata verifies that the encoder the anchor
// attachment uses produces exactly the attributes the readback parser consumes:
// table, chain, nested expressions and the canonical userdata bytes.
func TestNftRuleMessageRoundTripsUserdata(t *testing.T) {
	expression, err := nftRuleMessage(2, "sb_desync", "__sbds_v1", [][]byte{
		appendNetlinkMessage(nil, 0, 0, 0, nil), // placeholder bytes, not a real expression
	}, []byte("sbds:1:a:ip6:"+anchorEpochPlaceholder))
	if err != nil {
		t.Fatalf("build rule message: %v", err)
	}
	if expression.typ != unix.NFT_MSG_NEWRULE {
		t.Fatalf("message type = %#x", expression.typ)
	}
	if expression.flags&netlink.Excl != 0 {
		t.Fatal("a rule add must not be exclusive")
	}
	reply := nftReply{typ: uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWRULE,
		seq: 9, data: expression.data}
	_, attrs, err := nftMessageData(reply)
	if err != nil {
		t.Fatalf("parse built message: %v", err)
	}
	if table, ok := nftAttrString(attrs, unix.NFTA_RULE_TABLE); !ok || table != "sb_desync" {
		t.Fatalf("table attribute = %q,%v", table, ok)
	}
	if chain, ok := nftAttrString(attrs, unix.NFTA_RULE_CHAIN); !ok || chain != "__sbds_v1" {
		t.Fatalf("chain attribute = %q,%v", chain, ok)
	}
	userdata, ok := nftAttrBytes(attrs, unix.NFTA_RULE_USERDATA)
	if !ok || string(userdata) != "sbds:1:a:ip6:"+anchorEpochPlaceholder {
		t.Fatalf("userdata = %q,%v", userdata, ok)
	}
	if _, ok := nftAttrBytes(attrs, unix.NFTA_RULE_EXPRESSIONS); !ok {
		t.Fatal("expression list attribute is missing")
	}
}

// TestNftDeleteRuleCarriesExactHandle pins the rule-removal shape: the marker
// chain is shared, so a delete without an explicit handle would remove every
// rule of the chain and is never built here.
func TestNftDeleteRuleCarriesExactHandle(t *testing.T) {
	request := nftDeleteRuleMessage(2, "sb_desync", "__sbds_v1", 0x1122334455667788)
	if request.typ != unix.NFT_MSG_DELRULE {
		t.Fatalf("message type = %#x", request.typ)
	}
	_, attrs, err := nftMessageData(nftReply{data: request.data})
	if err != nil {
		t.Fatalf("parse delete: %v", err)
	}
	handle, ok := nftAttrUint64(attrs, unix.NFTA_RULE_HANDLE)
	if !ok || handle != 0x1122334455667788 {
		t.Fatalf("handle = %#x,%v", handle, ok)
	}
}

// TestNftAnchorUserdataRejectsMalformedInput pins the strict grammar: the
// metadata writer errors instead of truncating or normalizing.
func TestNftAnchorUserdataRejectsMalformedInput(t *testing.T) {
	valid := anchorMarkerUserdata("ip", anchorEpochPlaceholder)
	if valid != "sbds:1:a:ip:"+anchorEpochPlaceholder {
		t.Fatalf("anchor userdata = %q", valid)
	}
	cases := []string{
		"sbds:1:a:ip:", // missing epoch
		"sbds:1:a:ip6:" + anchorEpochPlaceholder[2:], // short epoch
		"sbds:2:a:ip:" + anchorEpochPlaceholder,      // wrong version
		"sbds:1:x:ip:" + anchorEpochPlaceholder,      // unknown kind
		"sbds:1:a:inet:" + anchorEpochPlaceholder,    // unknown family
		"sbds:1:a:ip:" + anchorEpochPlaceholder + "\x00",
	}
	for _, value := range cases {
		if _, err := parseAnchorUserdata(value); err == nil {
			t.Fatalf("malformed userdata %q was accepted", value)
		}
	}
}
