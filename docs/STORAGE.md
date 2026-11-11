# Storage

SAdns keeps history and settings in one **data directory**:

| Platform | Default |
|---|---|
| Windows | `%AppData%\SAdns` |
| macOS | `~/Library/Application Support/SAdns` |
| Linux / BSD | `$XDG_CONFIG_HOME/sadns` (`~/.config/sadns`) |
| Docker | `/data` |

Override with `--data-dir` or `SADNS_DATA_DIR`.

```
config/settings.json         preferences and Auto Run configuration (versioned)
config/schedule-state.json   last run, next run, skips, failures
history/index.json           one summary row per scan (versioned)
history/reports/<id>.json.gz the full report for each scan
secrets/auth.json            server-mode password hash (PBKDF2-SHA256, 600,000 iterations)
```

Measurements (`history/`), preferences (`config/`) and secrets (`secrets/`) are separate, so each can be
backed up, wiped or permissioned on its own. Everything is created with mode 0700 (directories) / 0600
(files): reports contain local addresses, hostnames and resolver details.

## Safety

- **Atomic writes.** Every file is written to a temporary file in the same directory, fsynced, then
  renamed over the target, and the directory is fsynced. A crash leaves the old or the new file, never a
  torn one. Leftover temporary files are removed at start.
- **Order.** A report is written before its index row. A crash in between leaves an orphan report, which
  is adopted on the next start; an index row whose report vanished is dropped.
- **Corruption.** An unreadable index is renamed to `index.json.corrupt-<time>` and rebuilt from the
  reports. Unreadable settings are set aside the same way and defaults (Auto Run off) are used, with a
  warning in the UI.
- **Versioning.** `index.json` and `settings.json` carry a `version`. Older versions are migrated on load;
  a newer version than the binary understands stops startup instead of being overwritten.
- **Imports** are size-limited (16 MiB), schema-checked (`sadns/report/v1`) and stored as received.

## Retention

The newest *N* unpinned scans are kept (default 100, 1–5000). Pinned scans do not count towards *N* and
are never deleted automatically (at most 500 pins), so pinning can never push out a scan you just ran.
Lowering *N* or unpinning applies retention immediately, deleting the oldest unpinned scans first.
Partial scans (cancelled, timed out, failed) are stored too and marked as such.

## Why not SQLite?

| Option | Verdict |
|---|---|
| **SQLite via cgo** (`mattn/go-sqlite3`) | Breaks the single static, cross-compiled binary (needs a C toolchain per target, including Windows/arm64). |
| **SQLite in pure Go** (`modernc.org/sqlite`) | Adds a ~10 MB, multi-module dependency to a project with zero dependencies, and is a large supply-chain surface for little gain. |
| **Embedded KV** (bbolt, Badger) | Still a dependency; data becomes opaque to users who want to inspect or back it up. |
| **Files (chosen)** | No dependency, inspectable with any text tool, trivially backed up, and safe with atomic renames. |

The workload is small and simple: a few scans per hour at most, a few thousand rows, a single writer
process. Queries are "list newest first" and "load one", which the in-memory index answers directly.
Measured on a 2-vCPU Xeon (`go test -bench . ./internal/store`): saving a report (gzip, fsync, index
rewrite) takes about 7 ms, loading one about 0.08 ms. If history ever needs ad-hoc queries over tens of
thousands of scans, the index file can be migrated to SQLite behind the same `store.History` API without
touching callers.
