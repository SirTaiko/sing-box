// Package tools implements the offline operator tooling exposed by
// `sing-box tools desync`.
//
// The package is deliberately independent of the runtime: it never creates a
// sing-box client, never loads a configuration and never starts a service. All
// entry points take an explicit io.Reader/io.Writer pair plus injectable
// resolver/clock seams so they can be exercised hermetically.
//
// # Upstream provenance
//
// ip2net.go is an independent Go implementation of the aggregation algorithm in
// bol-van/zapret v72.9 (commit c849e55ef0f1c244206f5a05ff7b1ab41a3824ee),
// ip2net/ip2net.c, which is distributed under the MIT license:
//
//	MIT License
//
//	Copyright (c) 2016-2024 bol-van
//
// dnsmsg.go and the mdig batch driver in mdig.go implement the DNS query blob
// construction, DNS answer extraction and batch resolver behavior of
// mdig/mdig.c from the same revision and are covered by the same notice.
//
// The Go code below is not a translation of the C source line by line; it
// reproduces the pinned observable semantics that are documented next to each
// function, and it replaces unchecked C arithmetic and unbounded buffers with
// bounded, explicit Go equivalents. The deliberate divergences known to this
// implementation are listed in docs/configuration/direct-desync-tools.md; that
// list is not a completeness or full-parity claim.
package tools
