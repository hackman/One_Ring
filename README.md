# One Ring — whois

> *One Ring to query them all.*

A multi-core WHOIS server in Go that downloads, merges, and serves the bulk
RPSL dumps of all five Regional Internet Registries (RIPE, ARIN, APNIC,
LACNIC, AFRINIC).

I built this prject specifically to support my [Willow](https://github.com/hackman/willow) project.
So I have a local cache when querying the whois DB.

## Features

- Implements the WHOIS protocol (RFC 3912) and you can run it on non-standard 
  port.
- Merges all five RIR databases into a single in-memory index, so one query
  works regardless of which registry owns the address space.
- Periodically polls each upstream with conditional `If-Modified-Since`, so
  the polling itself is cheap; the in-memory store is only rebuilt when at
  least one source actually changed. Scheduler combines a configurable
  polling cadence (`poll_interval`) with a UTC time-of-day anchor
  (`daily_at`) that guarantees one fresh attempt shortly after the daily
  publish window.
- Streaming RPSL parser; indexed in-memory store with:
  - primary key (per object class),
  - nic-hdl (for `person` and `role`),
  - domain name,
  - a 128-bit binary trie of `inetnum` / `inet6num` / `route` / `route6`
    prefixes — longest-prefix-match returns the most specific allocation.
- IP allow / deny lists implemented as a **BERT** (Binary Encoded Radix
  Tree): a 128-bit patricia trie that handles v4 and v6 together with
  longest-prefix semantics.
- Per-source token-bucket rate limiter with `/24` (v4) and `/48` (v6)
  aggregation.
- Goroutine-per-connection with a concurrency cap; scales across all cores.
- **Live stats dashboard** (modern dark-theme UI, single static HTML file).
  Stats are atomically dumped to a JSON file at a configurable cadence
  (sub-second supported) and served by an optional embedded HTTP listener.
  See active connections, what they're requesting, how long they've been
  open, and how much data they've moved — server-status-style.

## Build & run

```bash
go build -o whoisd .
./whoisd -config config.yaml
```

First start downloads several GiB of `.gz` files into `var/dbase/` (one
subdirectory per source) and indexes them.

## Querying

```bash
whois -h 127.0.0.1 -p 4343 8.8.8.8
whois -h 127.0.0.1 -p 4343 AS3333
whois -h 127.0.0.1 -p 4343 -- '-m 193.0.0.0/16'
```

Supported flags: `-r` (no related), `-x` (exact prefix), `-m`/`-M` (more-
specific), `-l`/`-L` (less-specific), `-b` (abuse contact).

## Stats dashboard

If `stats.http_bind` is set (default `127.0.0.1:8080`), open it in a
browser. The dashboard polls `/stats.json` on the same listener.

Alternatively, every `stats.dump_interval` (default 500ms; sub-second is
fine) the server atomically writes `stats.dump_path` (default
`./var/stats/stats.json`). Point any static webserver at the dump
directory and consumers can fetch it cross-origin.

## Configuration

See [`config.yaml`](config.yaml). All fields have defaults; an empty file
is valid.

| Section      | Notes                                                        |
|--------------|--------------------------------------------------------------|
| `server`     | bind address, deadlines, concurrency cap                     |
| `dbase`      | per-source list (5 RIRs) + polling cadence + daily anchor    |
| `acl`        | default policy + allow/deny CIDR lists (BERT)                |
| `rate_limit` | token-bucket per source with v4/v6 aggregation               |
| `stats`      | dump cadence (sub-second OK), JSON path, HTTP bind           |
| `log`        | slog text handler level                                      |

## Layout

```
main.go                entrypoint + signal handling + refresh loop
internal/config/       YAML loader + defaults + validation
internal/acl/          BERT prefix trie (allow / deny)
internal/ratelimit/    token bucket + idle GC
internal/ripe/         downloader, RPSL parser, indexed store, manager
internal/server/       RFC 3912 TCP server + query handler + stats hooks
internal/stats/        live registry, JSON dumper, embedded HTTP dashboard
```

## Notes

- Memory footprint scales with the size of the merged store. With all five
  RIRs loaded, expect ~20–30 GiB resident.
- Binding to port 43 requires either root or
  `setcap cap_net_bind_service=+ep ./whoisd`.

