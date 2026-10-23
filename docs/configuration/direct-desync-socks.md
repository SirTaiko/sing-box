# SOCKS inbound destination policy: `no_resolve` and `resolver_concurrency`

These two optional fields extend the existing `type: "socks"` inbound. They are
console configuration only and involve no Desktop, service, RPC or installer
surface. Both fields are absent by default and an absent field keeps the
previous sing-box behavior: the inbound neither refuses domains nor performs
any DNS lookup of its own.

Reference intent: bol-van/zapret v72.9
(`c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`), `tpws/tpws.c` `--no-resolve`
and `--resolver-threads`. The integration reuses the existing sing-box
protocol parser, `DNSRouter` and `domain_resolver`; it does not create a second
proxy, parser, resolver, cache or worker pool.

## Shape

```json
{
  "type": "socks",
  "tag": "socks-in",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "users": [
    {"username": "admin", "password": "admin"}
  ],
  "domain_resolver": "dns-local",
  "no_resolve": true,
  "resolver_concurrency": 8
}
```

## `no_resolve`

`no_resolve` refuses a CONNECT request whose original wire form is a domain (SOCKS5 ATYP=3 or the SOCKS4a hostname form, including IP-looking names)
name. The decision is made on the destination that the existing SOCKS parser
produced, before route rules, sniffing or any DNS query run, and it is applied
to SOCKS4a as well as SOCKS5 CONNECT.

- SOCKS5 uses the existing lazy handshake error mapping. The refusal is
  reported as the protocol's ruleset-denied reply code `2`; no reply code is
  guessed by the inbound, and the ordinary sing-box error mapping is exercised.
- SOCKS4a reuses the existing SOCKS4 failure response of the same lazy
  handshake path (reply code `0x5B`); the shared sing writer emits its normal
  four-byte frame for a response without a bind address.
- Literal IPv4 and IPv6 destinations are not affected and keep working.
- UDP ASSOCIATE, username/password authentication and UDP-over-TCP control
  requests are not disabled. The synthetic UoT destination
  (`sp.v2.udp-over-tcp.arpa`, `sp.udp-over-tcp.arpa`) is a transport control
  request, not a host to resolve, and stays untouched.
- The refusal is not a route rule and not a DNS rule: it cannot be overridden
  by `route` or `dns` configuration.

Known parser boundary (superseded by the maintained wire provenance): the
shared sing SOCKS parsers normalize an address field whose *text* parses as an
IP into a literal address before the inbound handler receives it
(`socks4.ReadRequest0` and the SOCKS5 address serializer both call
`metadata.ParseSocksaddrHostPort`). The maintained provenance patch
(`release/patches/sing-socks-wire-contract.patch`, contract
`direct-desync/socks-wire-contract/v1.1`) makes that normalization no longer
lossy for this decision: the shared handshake publishes the original wire
family of the parsed request (`socks.RequestMetadata.DestinationFamily` - the
SOCKS5 `ATYP` byte and the SOCKS4a `0.0.0.x` hostname form), so a numeric-looking
domain destination keeps its `ATYP=3` provenance and is refused exactly like any
other domain. A request whose wire provenance is missing or inconsistent with
the normalized destination fails closed instead of being treated as a literal.
Literal `ATYP=1`/`ATYP=4` destinations are unaffected, and a 16-byte IPv4-mapped
`ATYP=4` address keeps flowing as the IPv4 literal it denotes.

## `resolver_concurrency`

`resolver_concurrency` is an optional integer in the range `1..300`. When it
is present, the inbound resolves a domain destination through the existing
DNS router before route selection and passes the resolved addresses to the
route layer together with the original domain destination, so domain-based
route rules keep matching while the dialer uses the addresses that were
actually resolved.

- Slots are per inbound and exist only when the field is configured. A
  configuration without `resolver_concurrency` performs no inbound lookup at
  all, even when `domain_resolver` is set.
- A slot is acquired cancellably before the lookup and released immediately
  after it, not at the end of the connection.
- Literal destinations never acquire a slot and never trigger a lookup.
- Waiting lookups are bounded by `tcp_max_connections` when that admission
  limit is configured, otherwise by 10000. A request that arrives when the
  queue is full is refused immediately instead of blocking; the client gets
  the ordinary SOCKS failure reply for a lookup failure (SOCKS5 code `1`).
- The lookup runs against the existing `DNSRouter`, so DNS rules still apply.
  `domain_resolver` selects the DNS transport and carries its `strategy`,
  `timeout`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl` and
  `client_subnet` options. Without `domain_resolver` the ordinary default
  resolver selection of the dialer package applies.
- Answer order is the order produced by the configured DNS strategy; no
  byte-equivalence with an OS `getaddrinfo` implementation is promised.
- A canceled lookup releases its slot, and a result that arrives after
  cancellation is discarded instead of being routed. Cancellation is driven by
  the connection context (inbound shutdown or a canceled caller context);
  there is no speculative read of the client socket while a lookup is in
  flight, so pipelined application bytes are never consumed by this path.

## Interaction

| `no_resolve` | `resolver_concurrency` | Behavior |
|---|---|---|
| absent | absent | Previous sing-box behavior; no inbound lookup. |
| `true` | absent or set | Domain destinations are refused before route/sniff/DNS; literals pass. |
| absent | set | Domain destinations are resolved with bounded slots; literals pass. |

`no_resolve` is evaluated first, so a refused domain never consumes a resolver
slot and never performs a DNS query.

## Logs and errors

A `no_resolve` refusal is logged at debug level. A failed lookup is logged as
an error and reported to the client through the existing lazy handshake
failure path. The inbound never writes a success reply for a refused or failed
destination.
