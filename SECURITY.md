# Security

SealGate is an additional layer of defense for AI agents. It is not a certified safety system and it does not replace sandboxing, least-privilege credentials or a review of the tools you connect.

## What SealGate does not protect against

- **Content.** SealGate checks where an email goes and whether forbidden patterns appear. It does not judge whether an allowed text is false, offensive or cleverly disguised confidential information.
- **Open-ended tools.** A tool like "run any shell command" cannot be checked meaningfully. Do not approve it.
- **Bugs in the target server.** If the real MCP server has a flaw that allowed inputs can trigger, the gateway does not help.
- **Bypass.** SealGate only protects calls that go through it. If the agent has another path to the same system, that path is unprotected.
- **Information flow.** Values are checked against static rules, not by where they came from. An injected instruction can still cause harm within the allowed limits (for example an allowed recipient with misleading content).
- **Concurrent gateways.** Rate limits and rolling sums are stored on disk and survive a restart, but the counter file is not locked. Two gateways that decide at the same instant can both let a call pass.
- **Truncated audit logs.** Changed or removed lines in the middle of an audit log are detected; missing lines at the end are not.
- **Access to ~/.sealgate.** Keys, the emergency stop, counters and pending human approvals live there as files. No tool of the agent may ever reach this directory. SealGate refuses paths into it, but other tools on the same machine could still reach it. Approvals are signed, so such a program cannot approve a call or sign a policy without your password. It can still block work (set the emergency stop, damage the counter file) and it can reset the counters by deleting the counter file.

## Reporting a vulnerability

Please open a GitHub security advisory for this repository (Security tab, "Report a vulnerability") instead of a public issue. Include the policy, the call sequence and what you expected to happen.
