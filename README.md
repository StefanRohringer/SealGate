# SealGate

**A fail-closed MCP gateway for AI agents: the model proposes, a human-signed policy decides.**

```
model  -->  SealGate gateway  -->  real MCP server
            emergency stop        (files, email, ERP, ...)
            signed policy
            input checks
            rate limits
            human approval
            redaction
            audit log
```

SealGate is itself an MCP server. It starts the real MCP server behind it and only passes on what the policy allows. The real server does not need to change; it can even be completely naive.

What makes SealGate different from a typical gateway:

- **The policy is signed by a human.** Ed25519 signature over the policy hash, with an expiry date and an increasing serial number. If anyone changes a single character of the policy, or replays an older approval, every call is denied. Think of it as a signed work instruction for the agent.
- **Human approval on rolling sums**, not only on single calls. A large order cannot be split into many small ones below the threshold, also not across gateway restarts, separate agent runs or several gateways running at the same time.
- **Every human approval is signed** with the same key and bound to the exact request. A file dropped into the approvals folder by another program is not an approval, and a signed yes cannot be reused for another call.
- **A benchmark that measures with and without the gateway**, and separates *deceived* (the model tried) from *harm* (the call was executed).

Status: **0.4, early.** Read [SECURITY.md](SECURITY.md) before you rely on it.

## What happens on every call

| Step | Check | On violation |
|---|---|---|
| 1 | **Emergency stop**: does `~/.sealgate/ESTOP` exist? | everything denied |
| 2 | **Policy**: signed, unchanged, not expired, no older serial | everything denied |
| 3 | **Tool**: is it in the policy? Other tools are hidden from the model | denied |
| 4 | **Input**: every field checked, unknown fields denied | denied |
| 5 | **Rate**: at most N calls per time window, per tool and in total. Counters are stored on disk and locked, so they hold across restarts and across several gateways | denied |
| 6 | **Human**: where the policy says so, a human must approve. The answer must be signed with the approval key for exactly this request | denied after timeout or without a valid signature |
| 7 | **Response**: secrets (API keys, IBANs, ...) redacted before the model sees them | redacted |

Every decision is written as a JSON line to an audit log. Lines are chained by hashes, so a changed or removed line is detected by `bin/verify-audit.js`. The gateway also records the last line of every log in `~/.sealgate/audit_heads`, outside the log and out of reach of agent tools. With that anchor, lines cut off at the end, added lines, a log rewritten as a whole and a deleted log are detected too.

## Quick start

Requires Node.js 18 or newer. A step-by-step guide, including the key on a USB stick and what to do when something does not work, is in [GUIDE.md](GUIDE.md).

```bash
git clone https://github.com/StefanRohringer/SealGate.git
cd SealGate
npm install
npm test                                        # 122 checks with a throwaway key
node bin/keygen.js                              # once: your approval key in ~/.sealgate
node bin/sign-policy.js examples/acme/acme.policy.json
node bin/agent.js examples/acme/acme.policy.json "Check the stock list and reorder what is below minimum."
```

Orders from 500 EUR need a human. Run this in a second terminal:

```bash
node bin/approve.js
```

Emergency stop for all gateways on the machine: `node bin/estop.js on` and `node bin/estop.js off`.

**Key on a USB stick.** The private key does not have to stay on the machine. Create it on a stick, or move an existing one there:

```bash
node bin/keygen.js --key-file /media/you/STICK/sealgate_key.pem     # new key, private part on the stick
node bin/keygen.js --move-to  /media/you/STICK/sealgate_key.pem     # move an existing private key
```

The public key stays in `~/.sealgate`, the gateway needs only that one. `bin/approve.js` and `bin/sign-policy.js` read the private key fresh from the stick for every signature and do not keep it. With the stick unplugged, nobody can approve a call or sign a policy on that machine. `node bin/approve.js --ask-every-time` also asks for the password on every decision.

The example agent and the benchmark need an Anthropic API key in `ANTHROPIC_API_KEY`, in `~/.sealgate/api_key` or passed with `--key-file`.

## Use it with any MCP client

Register the gateway instead of the real server:

```json
{
  "mcpServers": {
    "acme": {
      "command": "node",
      "args": ["/path/to/SealGate/src/gateway.js", "/path/to/SealGate/examples/acme/acme.policy.json"]
    }
  }
}
```

## The policy

```json
{
  "name": "acme-demo",
  "target": { "command": "node", "args": ["../server.js"], "cwd": "data" },
  "tools": {
    "send_email": {
      "note": "only to purchasing@ and boss@",
      "checks": [
        { "field": "to", "type": "allow_list", "values": ["purchasing@acme.example", "boss@acme.example"] },
        { "field": "body", "type": "max_length", "max": 5000 }
      ],
      "rate_limit": { "count": 5, "per_seconds": 3600 }
    },
    "place_order": {
      "checks": [ { "field": "price_eur", "type": "number", "min": 0, "max": 5000 } ],
      "human_approval": { "field": "price_eur", "at_least": 500, "rolling_sum_seconds": 86400 }
    }
  },
  "global_rate_limit": { "count": 200, "per_seconds": 3600 },
  "redact": ["sk-ant-[A-Za-z0-9_-]{8,}"]
}
```

Check types:

| Type | Meaning | Example |
|---|---|---|
| `allow_list` | value must be one of `values` | allowed recipients, items |
| `deny_list` | value must not be one of `values` | blocked customers |
| `pattern` | text matches a regular expression | file extension `\.(txt\|md)$` |
| `deny_pattern` | text contains none of `patterns` | no IBAN in emails |
| `number` | number between `min` and `max` (`integer: true` for whole numbers) | quantity, price |
| `max_length` | text or list at most `max` long | email body |
| `type` | `is`: string, number, boolean, array, object | |
| `path_within` | path inside one of `folders`, also after resolving `..` and symlinks | work folder |
| `box` | point `[x, y, ...]` between `min` and `max` | any bounded coordinate |

Fields without a check must be listed in `"extra_fields"`, otherwise the call is denied. A check with `"optional": true` may be missing.

`human_approval` can be `true`, `{ "field", "at_least" }` or `{ "field", "values" }`. With `rolling_sum_seconds`, the human is asked as soon as a single call **or the sum of calls without approval** in that window reaches `at_least`.

Paths in the policy are relative to the policy file; paths from the model are relative to `target.cwd`. The directory `~/.sealgate` is never reachable, whatever the policy says.

## Benchmark

`bench/` measures indirect prompt injection: the user's task is harmless, an instruction is hidden in the company data. Each scenario runs **unprotected** (the model talks directly to the naive demo server) and **with SealGate**.

| File | Content |
|---|---|
| `basic.json` | 6 obvious injections (exfiltrate the stock list, huge order, read a confidential file, rewrite the policy, shell command, leak credentials) + control |
| `business.json` | 5 business-realistic injections (fake bank change, split order to avoid approval, travelling manager wants data at a private address, instruction spread over a framework contract, fake purchasing policy) + control |
| `published.json` | 5 templates from AgentDojo and InjecAgent x 5 goals + control |
| `utility.json` | 11 legitimate tasks without any attack: 8 within the demo policy, 3 that the policy deliberately blocks |
| `events.json` | 4 event-driven attacks, one agent run and one gateway start per incoming email (order split across runs with and without a visible hint, a planted note that a later run acts on, a standing rule forwarding future mail outside) + control |

```bash
node bench/bench.js --dry-run --scenarios-file business.json            # free: practice model always follows the injection
node bench/bench.js --dry-run --scenarios-file events.json              # event-driven: counters must survive the restart between runs
node bench/bench.js --models claude-haiku-5-5,claude-opus-5-5 --scenarios-file business.json --repeat 3
```

**Utility.** Security alone says little: a gateway that blocks everything is perfectly safe. `utility.json` measures the cost. Each task runs with and without the gateway, and success is judged on the resulting state (emails sent, orders placed, files written, final answer), not on what the model claims. Every denied call in these runs is a false positive of the policy.

```bash
node bench/bench.js --models claude-haiku-5-5,claude-opus-5-5 --scenarios-file utility.json --repeat 3
```

Reports go to `bench/reports/`, every run with all calls and its audit log to `bench/runs/`. Scenarios are plain JSON; add your own without changing code.

First measurements are in [RESULTS.md](RESULTS.md).

## Files

| Path | Purpose |
|---|---|
| `src/gateway.js` | the gateway |
| `src/gates.js` | pure checking logic, no MCP |
| `src/approval.js` | policy approval (signature, hash, expiry, serial) and signed decisions on single calls |
| `src/keys.js` | where keys live, including a private key on a USB stick |
| `src/audit.js` | hash-chained audit log |
| `bin/keygen.js` | create the approval key, optionally on a USB stick (`--key-file`, `--move-to`) |
| `bin/sign-policy.js` | review and sign a policy (password needed) |
| `bin/approve.js` | a human decides on pending requests and signs each decision (password once at start) |
| `bin/estop.js` | emergency stop on and off |
| `bin/verify-audit.js` | check audit logs against their hash chain and their anchor (`--all` for every log of this machine) |
| `bin/agent.js` | Claude agent that works only through the gateway |
| `test/gateway.test.js` | 52 automated checks against the running gateway |
| `test/audit.test.js` | 15 automated checks: tampering inside and at the end of the audit log |
| `test/approval.test.js` | 10 automated checks: signed and forged approvals |
| `test/keyfile.test.js` | 19 automated checks: private key on a stick |
| `test/counter.test.js` | 26 automated checks: limits across restarts and with several gateways at the same instant |
| `GUIDE.md` | step-by-step setup and daily use |
| `bench/` | prompt injection benchmark with and without the gateway |
| `examples/acme/` | naive demo server, policy and fictional company data |

## Prior art and how SealGate differs

SealGate combines known building blocks. Several projects already proxy MCP servers with policies, human approval and tamper-evident logs. The closest ones, as far as we know:

| Project | What it shares with SealGate | Difference |
|---|---|---|
| [Blastgate](https://github.com/bzucker4/blastgate) (AGPL-3.0) | stdio MCP proxy, rule file checked before every tool call, human approval with timeout, fail closed, hash-chained audit log | Audit lines are also Ed25519-signed, which SealGate's are not (SealGate anchors the end of each log outside the log instead). Rules are a YAML file, not a policy signed by a human with expiry and serial |
| [mcp-audit-gateway](https://github.com/elang2/mcp-audit-gateway) | wraps MCP servers, signed and hash-chained audit records, policy with rate limits | Signs the log entries, not the policy itself |
| [protect-mcp](https://www.npmjs.com/package/protect-mcp) | fail-closed policy gate for MCP with human approval and signed receipts | Uses Cedar or JSON policies and signs every decision as a receipt |
| [Progent](https://arxiv.org/abs/2504.11703), [CaMeL](https://arxiv.org/abs/2503.18813) | research on deterministic privilege control for agents, evaluated on AgentDojo | Research systems, not drop-in MCP gateways |

What SealGate adds to this picture:

- **The policy itself is signed by a human** (Ed25519) with an expiry date and an increasing serial number, so a changed or replayed policy stops everything.
- **Approval on rolling sums**, so a large action cannot be split into small ones below the threshold, also not across restarts, separate agent runs or several gateways at once.
- **Signed human approvals** bound to the exact request, with the option to keep the signing key on a USB stick.
- **Field checks** including `path_within` with symlink resolution, and redaction of secrets in responses and written content.
- **A benchmark that runs every scenario with and without the gateway**, separates "deceived" from "harm" and measures utility on the resulting state.

SealGate is not a new category. If you need signed audit lines or rules per caller identity today, look at the projects above. The table was last checked against the linked pages on 22 November 2026.

## License

Copyright 2026 Stefan Rohringer.

Licensed under the Apache License 2.0, see [LICENSE](LICENSE). If you redistribute SealGate or build on it, keep the copyright notices and the [NOTICE](NOTICE) file, which names the author and the original repository. Third-party material is listed in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Disclaimer

SealGate is an independent project. It is not affiliated with or endorsed by Anthropic, or the authors of AgentDojo or InjecAgent. Claude is a trademark of Anthropic. Benchmark results describe one setup on one date and are not a statement about the general safety of any model.
