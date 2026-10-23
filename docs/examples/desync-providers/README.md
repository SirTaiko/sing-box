# Provider refresh examples

Every file here is an operator input example. Nothing is executed on
configuration load. See `docs/configuration/direct-desync-providers.md` for the
complete contract.

- `request-reestr.json` — remote acquisition of the pre-resolved reestr feed for
  both families, plus explicit local user and exclusion inputs (absolute paths
  must be replaced by the operator).
- `request-local-import.json` — fully offline import of captured snapshots for
  the same recipe. It performs no HTTP; explicit host inputs are still resolved
  through the mdig seam.
- `request-empty.json` — deliberate empty complete generation for a clean
  operator rollover.
- `rule-selector.json` — the optional `list_bundle` selector shape that the core
  owner attaches to a packet or stream rule. It is documentation of the settled
  schema, not a running configuration.

Publication:

```sh
sing-box tools desync list-refresh \
  --request docs/examples/desync-providers/request-reestr.json \
  --output-dir /var/lib/sing-box/desync/lists
```

Rollback to a previously committed generation (offline, no network):

```sh
sing-box tools desync list-refresh \
  --rollback 0123456789abcdef0123456789abcdef \
  --output-dir /var/lib/sing-box/desync/lists
```

Runtime inspection requires an already configured controller:

```sh
BOX_API_SECRET=... sing-box tools desync diagnostics \
  --server http://127.0.0.1:9090 --outbound zapret --kind status
```
