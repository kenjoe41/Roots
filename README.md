# Roots

[![Go Reference](https://img.shields.io/badge/go-reference-blue?logo=go&logoColor=white&style=for-the-badge)](https://pkg.go.dev/github.com/kenjoe41/Roots)
[![GitHub license](https://img.shields.io/badge/LICENSE-MIT-GREEN?style=for-the-badge)](LICENSE)

Roots walks public [Certificate Transparency](https://certificate.transparency.dev/) logs and
streams every hostname it finds (certificate `CommonName` and `DNSNames`) to stdout. It's a
firehose over CT logs, not a targeted lookup: point it at nothing and it fetches from every log
server currently listed in Google's [log list](https://www.gstatic.com/ct/log_list/v3/log_list.json),
concurrently, forever (or until each log's tree is fully walked).

Pair it with `grep` to watch for domains matching a pattern, or feed it into other recon
tooling such as [goSubsWordlist](https://github.com/kenjoe41/goSubsWordlist).

## How it works

- Fetches the current CT log list, then spawns one goroutine per log server.
- Each log server is walked in `1000`-entry batches by `10` concurrent workers, with
  exponential backoff on transient fetch errors.
- Every valid hostname found (validated against RFC 6125 syntax rules) is printed to stdout,
  one per line, as soon as it's parsed — no buffering or deduplication.
- Progress and errors are written to stderr, so stdout stays a clean, pipeable domain list:

  ```shell
  ./Roots > domains.txt
  ```

## Resume support

Roots persists the last index processed for each log server under
`~/certwatch/logs/<log-server>.json`. On the next run, each log server resumes from its saved
index instead of starting over from zero — useful since some logs have hundreds of millions of
entries and a full walk can take a long time.

Delete `~/certwatch/logs/` to force a full re-walk from scratch.

## Install

```shell
go install -v github.com/kenjoe41/Roots@latest
```

## Usage

```shell
Roots > domains.txt
```

There are no flags. Roots always walks every log in the current CT log list; interrupt it
with Ctrl-C at any point — progress up to the last completed batch per log is saved.

## Caveats

- This is a high-volume crawl: CT logs are large, and Roots deliberately does not rate-limit
  itself beyond the built-in backoff-on-error. Be considerate of the log operators you're
  hitting.
- No deduplication is performed. The same hostname will appear multiple times if it shows up
  in multiple certificates (SAN reissues, multiple logs, etc.) — dedupe downstream if needed,
  e.g. `./Roots | sort -u`.

## License

MIT — see [LICENSE](LICENSE).
