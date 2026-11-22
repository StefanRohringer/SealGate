# Changelog

## 0.3.1 (2026-11-22)

Found in a review of the whole repository after 0.3.0.

### Fixed

- Two gateways with the same policy that started in the same millisecond wrote into the same audit file, which broke its hash chain. Every gateway now gets its own audit file (the name contains the process id, and a taken name gets a number).
- `bin/approve.js` and `bin/keygen.js` asked for the password before noticing that the stick was missing or that a key already existed. They now check first.
- `GUIDE.md`: the entry for "answer is not signed with the approval key" did not mention that `approve.js` itself writes an unsigned answer when you say no with the stick unplugged.

### Changed

- CI also runs the event-driven dry run.

## 0.3.0 (2026-11-22)

### Security

- Counters are now locked. Checking the rate limit, looking at the rolling sum and booking the call happen as one step under a lock file, so several gateways with the same policy that decide at the same instant can no longer all let a call pass. Before, eight gateways deciding at once on orders of 496 EUR let more than one pass in 6 of 10 trials. The lock is not held while waiting for a human; after a yes the call is booked in a second locked step that checks the rate limit again. A lock left by a crashed gateway is taken over; if the lock cannot be had within 5 seconds, the call is denied.
- Human approvals for single calls are now signed. `bin/approve.js` signs every decision with the approval key (it asks for the password once at the start), and the gateway accepts a yes only if the signature is valid, made with the approval key and bound to exactly that request. Before, any program that could write into `~/.sealgate/approvals/decided` could approve a call with a plain JSON file.
- The private key can live outside `~/.sealgate`, for example on a USB stick: `node bin/keygen.js --key-file <file>` for a new key, `--move-to <file>` for an existing one. `bin/approve.js` and `bin/sign-policy.js` read the key fresh for every signature and do not keep it, so with the stick unplugged nothing can be approved or signed. The key file is never reachable for agent tools, wherever it lives.

### Changed

- The format of the answer files in `~/.sealgate/approvals/decided` changed. Unsigned answers are denied.
- `bin/approve.js` asks for the password at the start (or for every decision with `--ask-every-time`).

### Added

- `test/approval.test.js` and three checks in `test/gateway.test.js`: unsigned, foreign-key and replayed approvals are denied.
- `test/keyfile.test.js`: key on a stick, stick unplugged, moving a key.
- `test/counter.test.js`: eight real processes deciding at the same instant, stale and held locks.
- `GUIDE.md`: step-by-step setup and daily use.

### Known limits

- Counters are per machine. Gateways on different machines do not share them.
- A USB stick is not a hardware security key: while it is plugged in, the encrypted key file can be copied.
- Missing lines at the end of the audit log are not detected.

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
