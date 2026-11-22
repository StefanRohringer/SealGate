# Changelog

## 0.2.0 (2026-11-22)

### Security

- Rate limits and rolling sums now survive a gateway restart. They used to live in memory, so restarting the gateway reset them: with one gateway start per agent run, an order split into several parts could pass the approval threshold. The counters are now stored per policy in `~/.sealgate/counters/` (inside the protected SealGate directory), read fresh before every decision and written after every change. If the file cannot be read or written, the call is denied.

### Added

- Event-driven benchmark scenarios (`bench/scenarios/events.json`): every incoming email starts its own agent run with a fresh conversation and a freshly started gateway. Four attacks and a control.
- `create_rule` in the demo server (standing inbox rules). The demo policy requires human approval for every rule.
- `test/counter.test.js`: limits across restarts, shared counters, expiry, fail closed. `npm test` runs it before the gateway test.
- Results of the event-driven runs in `RESULTS.md`.

### Changed

- The benchmark starts every run with empty counters.
- `SECURITY.md` no longer lists restarts as a gap; it lists concurrent gateways instead.

### Known limits

- Two gateways that decide at the same instant can still both let a call pass: the counter file is not locked. Runs one after another are covered.
- Human approvals are not signed yet, and missing lines at the end of the audit log are not detected.

## 0.1.0 (2026-11-19)

First public release.
