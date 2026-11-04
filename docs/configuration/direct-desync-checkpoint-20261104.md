# Direct desync — intermediate progress checkpoint (candidate 32)

This document records the state of the existing `direct-desync` work at the
2026-11-04 checkpoint commit. It is an **intermediate progress checkpoint**, not
acceptance, not a release, and not a claim that the current candidate works.

Checkpoint base: dirty worktree at `47076aedaa08e09006ea5a245312b60b994c3f8a`
on `checkpoint/direct-desync-candidate32-20261029`. The tracked diff, the new
source/tests and this document are the only things the checkpoint adds; no
source bytes were reformatted or regenerated for it.

Source identity at the checkpoint (SHA-256 of the working-tree files):

| path | SHA-256 |
| --- | --- |
| `common/desync/backend_windows.go` | `3a56ee890c71cf98abe17e71f76edfdf688074df65fa4c3f797a83c1f6b46b80` |
| `common/windivert/handle_windows.go` | `caaabd74aee83c8bbf68a761f1ebba637e143e8d92a7b9b4aa0ba7ab4abf745e` |
| `common/windivert/lifecycle.go` | `e6701f81fd32b37bce82efe3ec03493e46f02ac0c4cd6fba20f6e3eaed70e2d6` |

## Current status (unchanged by this checkpoint)

* Objective: **UNMET**. Aggregate: **INCOMPLETE**. Final gates: **NOT_RELEASED**.
* CPU objective: **UNMET**, performance **UNQUALIFIED**. The W1403 descriptor
  `A = 0.28125 s`, `B_SUM = 0.15625 s`, `C = 3.671875 s` is descriptive
  measurement only; it is not an established speedup.
* Current application behaviour: **FAIL**, cause **UNRESOLVED**. In the last real
  native run (W1407) the controlled arms produced `OFF = curl 28`,
  `reference = 0` (TLS handshake complete, HTTP 200 on the reference peer) and
  `integrated = 28`; only the CONNECT tunnel succeeded in the OFF/integrated
  arms, so TLS never completed on the current candidate.
* YouTube playback: **UNVERIFIED** — no browser session and no media counters were
  observed in that run.
* `Q1C6`: **PAUSED OPEN**. No regression attribution is claimed here: the
  executable, arm order and lifecycle sequencing changed since the earlier
  W1038 observation, so the negative result does not identify a cause.

## Reproduce the short checks

The Windows console build must use the audited Go 1.26.9 toolchain:

```sh
GO=/home/taiko/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64/bin/go

GOOS=windows GOARCH=amd64 python3 release/check-windows-adoption-go.py --go "$GO"
```

The portable WinDivert lifecycle checks run on the host without a device:

```sh
GOFLAGS=-mod=readonly GOPROXY=off GOWORK=off GOTOOLCHAIN=local \
    "$GO" test -count=1 -run TestIOLifecycle ./common/windivert/
```

Building `./common/dialer/` on Linux needs third-party modules that are not in
the offline module cache; the Windows/amd64 type-check
(`GOOS=windows GOARCH=amd64 go build ./common/desync/ ./common/windivert/
./common/dialer/`) is the check used at this checkpoint.

## Local evidence identifiers

These live outside the repository and are not committed:

* R1409 review artifact:
  `/home/taiko/code/singbox-worktrees/desync-network-repair-artifacts/t_e020e1e3`
  (`SHA256SUMS` SHA-256 `f02675d26650d304f09bf26f8ac4dd3d7ac82a64bbcbc28dafbb7842615acc41`).
* W1407 native inputs:
  `/home/taiko/code/singbox-worktrees/desync-network-repair-artifacts/t_86a0d6b5`
  (`SHA256SUMS` SHA-256 `0e48f33b66b8ad324276c72ea31950db666b112d6dc606173c2b2ec8484b5f66`);
  tested executable SHA-256 `1882b3ba62a237d696ee59c6398857d0d51880b8a6431abb9ba08488c140005f`.

The remaining work is to explain the integrated TLS failure and to verify
playback. Until then the candidate stays application-UNQUALIFIED and the final
gates stay closed.
