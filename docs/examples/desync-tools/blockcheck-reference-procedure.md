# Blockcheck reference comparison procedure (PENDING - NOT EXECUTED)

**Status: PENDING. Nothing in this document has been executed in this
environment.** No disposable Linux or Windows host was available, no packet was
captured, no DPI-affected path was contacted and no `desync.blockcheck/v1`
document with real `PASS` results exists. The companion template
`blockcheck-report-template.json` only contains `SKIP` cases for that reason.

This is the reproducible procedure an authorized, disposable lab run must
follow. The operator supplies the lab; this repository ships no lab credentials
and the procedure is not executed by the offline tools. Root's authorized
Ubuntu lab supersedes the earlier "no Linux VM available" draft statement;
native Linux/Windows results remain a separate evidence class until such a run
actually happens. The procedure itself defines what has to be recorded so that
two captures can be compared without guesswork, and so that a `PASS` cannot be
produced by hand-waving.

## Fixed inputs

| Item | Value |
|---|---|
| zapret revision (reference behavior) | `c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`, bol-van/zapret v72.9 |
| Flowseal configuration revision (regression input only) | `1.10.4` |
| capture tool | `tcpdump` on Linux, `pktmon` or WinDivert-based capture on Windows, exact version recorded per run |
| comparison target | a single host and port that the operator owns or is authorized to probe; recorded verbatim in the case `strategy` argv |
| payloads | the exact files supplied with the run, each recorded with `sha256sum` |

Payload hashes already pinned in this repository
(`docs/examples/desync/provenance.sha256`) must be reused unchanged when those
files are used:

| Payload | SHA-256 |
|---|---|
| `bin/tls_clienthello_www_google_com.bin` | `936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c` |
| `bin/tls_clienthello_4pda_to.bin` | `eefeaf09dde8d69b1f176212541f63c68b314a33a335eced99a8a29f17254da8` |
| `bin/stun2.bin` | `b7c2497496039c541f7337ac8536813f0a1cf52363ab2faa5213b7816d458813` |
| `bin/quic_initial_www_google_com.bin` | `f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a` |
| `bin/tls_clienthello_www_sferum_ru.bin` | `e6dd8d724eecc6a7340bf64e2ebec81c60bc4e078c6f702b4b6ba9bf184180ad` |

Any additional payload must be added to the report with its own hash; a payload
without a recorded hash invalidates the case.

## Case identity

One case is one `(platform, strategy, payload set, reference revision)` tuple.
The case `strategy` field carries the exact `--dpi-desync` argv, including every
value that changes the wire bytes, for example:

```text
--dpi-desync=fake,multisplit --dpi-desync-split-pos=1 --dpi-desync-fooling=ts
--dpi-desync-repeats=8 --dpi-desync-fake-tls=bin/tls_clienthello_www_google_com.bin
--dpi-desync-ttl=1
```

Rules:

- The argv string is identical on Linux and Windows. A platform that does not
  support a combination (for example upstream's unsupported
  OOB+disorder combination outside Linux) produces a `SKIP` with the exact
  unsupported-combination reason, never a `PASS`.
- The revision pair is the pinned pair above. Do not silently upgrade the
  reference revision; a different revision needs a new report.
- The Flowseal configuration is a regression input. A run with Flowseal config
  files records those files and hashes; it does not become the parity boundary.

## Execution steps (per platform, on a disposable VM)

1. Provision a disposable VM with no VPN, no split tunnel, no host firewall rule
   and no other traffic. Record the image name, kernel/OS build and capture tool
   version.
2. Verify the reference binaries and payloads against the hashes above; record
   `sha256sum` output for every payload and for the reference `nfqws`/`winws`
   binary.
3. Start the capture with a fixed filter that includes both directions of the
   target flow, for example:

   ```text
   tcp port 443 and host <recorded-target-ip>
   ```

4. Run the reference tool with the exact case argv, then run the same request
   through the sing-box implementation on the same VM image. Do not change the
   argv between the two runs.
5. Store the raw capture, the sing-box build identity, the full argv and the
   hashes in one immutable directory per case.
6. Normalize both captures (below) and compare. Record `PASS` only when the
   normalized streams are equal, `FAIL` with the first differing record when
   they are not, and `SKIP` with a reason for an unsupported platform
   combination or a missing capture.
7. Fill the evidence per case with the **relative** path of the stored directory
   and the `sha256` of the normalized capture file.

## Normalized packet comparison

The comparison is on the normalized TCP/IP stream, not on raw bytes. Normalize
only fields that are explicitly variable on the wire, and never normalize away
the field a case is testing:

- Drop link-layer headers only. Keep IP version, source/destination address,
  TTL/hop limit, the IPv4 `identification` field, IPv4 options, IPv6 extension
  headers and fragment headers. A case that tests `ip_id`, fooling options or
  fragmentation compares those fields explicitly rather than zeroing them.
- Keep transport ports and sequence/acknowledgement numbers. When the case does
  not test them, mask the initial sequence number (ISN) and TCP timestamps with
  a documented per-direction delta, and record the mask in the case metadata.
  Never mask the field under test.
- Verify TCP and IP checksums after materialization (after NIC offload), keeping
  offload state in the evidence. Do not zero checksums to make a comparison
  pass; a checksum mismatch is a case result, not normalization noise.
- Keep bidirectional payloads complete; order records by capture timestamp and
  keep both directions interleaved.
- Emit one line per record: `direction ip_version ttl flags seq ack payload_len
  payload_sha256`, with `direction` one of `c2s`/`s2c`, plus the explicitly
  retained fields of the case in a deterministic order. Add the retained-field
  list to the case metadata so two runs cannot silently normalize different
  fields.
- Two captures match when their normalized line sequences are identical. A
  difference in payload hash is reported with the affected record index and both
  hashes; a difference in ordering or count is a failure as well.
- Compare both egress and the receiving peer, and verify the receiver actually
  received the expected application data. A capture of one direction alone is
  not sufficient evidence for a transform case.

A comparison that only checks "the connection succeeded" or "the page loaded" is
not a valid result for this procedure.

## Result document

Assemble the cases into a `desync.blockcheck/v1` document and validate it with:

```text
sing-box tools desync blockcheck-report --input report.json --output normalized.json
```

The validator rejects unknown fields, duplicate ids, a `PASS` without evidence
metadata and any revision other than the pinned pair. A document produced by
this procedure must keep the raw captures; the tool only normalizes and checks
the metadata, it does not prove that the capture exists.
