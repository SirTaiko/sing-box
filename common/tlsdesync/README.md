# Experimental TLS packet strategies

Local experiment based on the fork's `stable` branch, revision
`d630fa94c53b2e2bdf256fad8b9d1cff809146ed` (after v1.14.3).
This is a new fork-specific route option, not an upstream sing-box setting.
It runs inside sing-box; no zapret process or VPS is involved.

`example.json` is a complete localhost-only test configuration for a Linux VM
whose physical interface is `eth0`. It uses current DNS answers and the
reverse-order strategy that succeeded in the home-VM HTTPS tests.
The experiment also produced intermittent failures: a later current-DNS run
of this exact example failed Discord and the YouTube homepage while the
thumbnail worked. Use it as a test template, not a reliable production bypass.

```json
{
  "action": "route",
  "outbound": "direct",
  "tls_desync": {
    "mode": "multisplit",
    "split": "1",
    "overlap": 681,
    "fake_sni": "www.google.com"
  }
}
```

Use a localhost mixed inbound and a direct outbound bound to the test
interface. Only matching IPv4 TCP connections are supported. The wrapper
requires a complete ClientHello in the first Write and in a single TCP segment
no larger than the socket MSS. Larger/partial hellos fail explicitly; packet
reassembly is not implemented. These tests therefore do not establish browser
compatibility with large post-quantum ClientHellos. QUIC/Discord voice UDP and
TUN integration are outside this experiment.

Options:

- `mode`: `multisplit` (default) or `multidisorder` (reverse segment order).
- `split`: ascending comma-separated byte offsets, optionally `midsld`
  (middle of the label before the final dot). Default `1,midsld`.
- `overlap`: false prefix length prepended to the first logical segment;
  its TCP sequence is shifted backwards by this length. Default 0, maximum
  4096; generated segments must still fit the MSS.
- `overlap_pattern`: optional file containing 1..16384 bytes. Its bytes are
  repeated/truncated to fill the prefix. Without a file, the cloned fake
  ClientHello is used. A nonzero overlap and fake_sni are required.
- `fake_sni`: name substituted in a clone of the actual ClientHello. Session
  ID, ciphers, key shares and extension order are preserved; random changes.
- `fake_repeats`: number of standalone fake packets, 0..16 (default 0).
- `fake_method`: `wrong-sequence` (default), `wrong-checksum`, `wrong-ack`,
  `wrong-md5`, or `ttl`. The TTL method requires `fake_ttl`.
- `fake_ttl`: optional fixed fake-packet TTL, 1..255. No automatic TTL probing.
- `segment_delay_ms`: optional delay between generated packets, 0..500.

The combined reverse+overlap mode keeps the multisplit-style prefix on the
first logical segment and then reverses the segments. This is not zapret's
second-segment overlap variant for multidisorder. The Flowseal-inspired tests
also do not reproduce its complete Windows/WinDivert pipeline or UDP profiles.

The Linux implementation creates a dedicated nftables table and NFQUEUE for
each selected socket's exact source/destination IPv4 address and TCP port
tuple. Original ClientHello packets (and their retransmissions) are replaced
by generated raw packets; subsequent data/ACKs are accepted unchanged. Original
TCP options and the socket's bound interface/routing mark are retained. The
internal raw socket adds mark bit `0x40000000` to bypass its own queue rule.
Do not use this experimental bit on a host where it has another routing role.
Root or CAP_NET_ADMIN plus CAP_NET_RAW is required.

Normal Close removes the private table before closing the queue. Abrupt
process termination can leave an inert table (queue bypass flag is enabled).
The VM harness also audits/removes only tables belonging to its test process;
never flush the machine's firewall to clean up this experiment.

Validation:

```sh
GOTOOLCHAIN=go1.26.8 go test -race ./common/tlsdesync ./option ./route/rule
GOTOOLCHAIN=go1.26.8 go test -c -o /tmp/desync-tests ./common/tlsdesync
# On the test VM, as root:
/tmp/desync-tests -test.v -test.run TestIntegrationStream -test.timeout 45s
```

The integration test checks real Linux reassembly of overlap/reordered/fake
packets and byte-for-byte delivery of the original hello plus later data.
Successful integration or config validation alone does not prove DPI bypass;
external HTTPS/application results and packet captures are required separately.

## Home VM results, 2026-10-13

- Main matrix: 18 configurations; four further split/delay tuning runs.
- A controlled A/B series pinned the same current IPv4 addresses in both
  modes. Plain direct failed all 12 API/homepage/thumbnail/WebSocket probes;
  reverse `1,midsld` passed all 12. TLS certificates were verified.
- Discord gateway returned HTTP 101 and Hello opcode 10. No logged-in session
  or voice UDP test was performed.
- YouTube extraction succeeded once with 24 formats and a 185292-byte MP4
  response from googlevideo.com (HTTP 206). A comparison of the same signed
  media URL and CDN IP failed plain direct twice; desync received 65536 bytes
  once and timed out once. Later extraction attempts also failed.
- Captures show real hello segments at relative sequence offsets such as
  `160,1,0`, sequence-overlap prefixes, and cloned/repeated fake session IDs.
  Capture coverage varies; immediate-mode capture was enabled for final
  tuning after short successful flows were found missing from some captures.
- Later current-DNS and tuning runs regressed. This demonstrates successful
  bypass attempts, not a stable general-purpose solution. Small split delays
  did not establish a reliable improvement.
- Pure Go race tests, option/rule tests, command build and nine root VM
  integration cases passed. Final VM cleanup found no test core/tcpdump,
  localhost listener or private nftables tables; routes/rules were unchanged.

Full local evidence: `/home/taiko/Documents/sing-box-antidpi-2026-10-13/native-desync/`.
