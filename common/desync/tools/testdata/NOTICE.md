# Test data provenance

Every file in this directory is synthetic. None of it was captured from a live
network, a real DPI-affected path or a vendor feed.

- `blockcheck/parser-input-synthetic.json` is a **parser test input** for the
  `desync.blockcheck/v1` validator. Its `PASS` case carries placeholder evidence
  metadata (`sha256` of 64 `a` characters) and must never be presented as a
  blockcheck result. The case ids start with `parser-` for that reason.
- `provider/provider-synthetic.txt`, `provider/exclude-synthetic.txt` and
  `provider/ip-synthetic.txt` are synthetic list snapshots used to pin the
  list-normalize behavior. They are not provider data and contain no user data.
- `provider/provider-synthetic.txt.gz` is the gzip form of
  `provider-synthetic.txt`, produced with `gzip -n -9` so it has no timestamp,
  name or OS byte and reproduces byte for byte.

The ip2net and mdig semantics reproduced by the package come from
bol-van/zapret v72.9, commit c849e55ef0f1c244206f5a05ff7b1ab41a3824ee,
files `ip2net/ip2net.c` and `mdig/mdig.c`, distributed under the MIT license,
Copyright (c) 2016-2024 bol-van.
