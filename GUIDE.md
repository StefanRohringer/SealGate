# SealGate step by step

This guide takes you from a fresh clone to an agent that works behind the gateway, with your approval key on a USB stick. The short version is in the [README](README.md); the limits are in [SECURITY.md](SECURITY.md).

## 1. What you need

- Node.js 18 or newer.
- An MCP server you want to protect. To try things out, the demo server in `examples/acme/` is enough.
- Optional: a USB stick for the private key.
- Only for the example agent and the benchmark: an Anthropic API key.

## 2. Install and test

```bash
git clone https://github.com/StefanRohringer/SealGate.git
cd SealGate
npm install
npm test
```

The tests use throwaway keys in a temporary folder. They do not touch `~/.sealgate`.

## 3. Create your approval key

SealGate uses one key pair for everything a human signs: policies and single approvals.

| Part | What it does | Where it lives |
|---|---|---|
| Public key | The gateway uses it to check signatures. It is not secret. | always `~/.sealgate/public_key.pem` |
| Private key | You use it to sign. It is encrypted with your password. | `~/.sealgate/private_key.pem`, or a file on a USB stick |

You create both parts with one command. Choose one of the two variants.

**Variant A: key on the machine**

```bash
node bin/keygen.js
```

**Variant B: private key on a USB stick**

Plug in the stick and find out where it is mounted:

```bash
ls /media/$USER/
```

Then create the key there, using the name the first command printed:

```bash
node bin/keygen.js --key-file /media/$USER/STICK/sealgate_key.pem
```

In both variants you choose a password of at least 12 characters. It is never stored. Without the private key file **and** the password there are no new signatures.

With variant B, signing works only while the stick is plugged in. `bin/approve.js` and `bin/sign-policy.js` read the key fresh from the stick for every signature and do not keep it.

**Back up the private key.** Copy the key file to a second stick and store it somewhere safe. If you lose the only copy, see "Lost stick or forgotten password" below.

**Move an existing key to a stick**

```bash
node bin/keygen.js --move-to /media/$USER/STICK/sealgate_key.pem
```

The file is copied, checked, and the original is deleted. Deleting does not wipe a disk. If that matters to you, create a new key on the stick instead.

## 4. Write and sign a policy

The policy is a JSON file that says which tools the agent may use and with which values. Start from `examples/acme/acme.policy.json`; the format is described in the README under "The policy".

Sign it (stick plugged in, if you use one):

```bash
node bin/sign-policy.js examples/acme/acme.policy.json
```

The command shows what you are about to approve: every tool, its checks, limits and where a human is needed. Type `approve`, then your password. The approval is written next to the policy as `*.approval.json` and is valid for 7 days. For a different period add the number of days: `node bin/sign-policy.js my.policy.json 30`.

Sign again whenever

- you changed the policy, even by one character,
- the approval expired.

Until then the gateway denies every call.

## 5. Put the gateway in front of your MCP server

In the policy, `target` says how to start the real server. In your MCP client, register the gateway instead of the real server:

```json
{
  "mcpServers": {
    "acme": {
      "command": "node",
      "args": ["/path/to/SealGate/src/gateway.js", "/path/to/my.policy.json"]
    }
  }
}
```

The model now sees only the tools named in the policy. To try it with the included example agent (needs an Anthropic API key in `ANTHROPIC_API_KEY` or `~/.sealgate/api_key`):

```bash
node bin/agent.js examples/acme/acme.policy.json "Check the stock list and reorder what is below minimum."
```

## 6. Approve single calls

Where the policy asks for a human (`human_approval`), the gateway waits for your decision. Open a second terminal (stick plugged in, if you use one):

```bash
node bin/approve.js
```

Enter your password once. For every request you see the tool and all values and answer `y` or `n`. Each decision is signed and belongs to exactly that request.

- No answer within the deadline (`human_approval_timeout_s` in the policy, default 120 seconds) counts as no.
- If the stick is unplugged when you answer `y`, `approve.js` asks you to plug it in.
- `node bin/approve.js --ask-every-time` asks for the password on every decision.

## 7. Emergency stop

```bash
node bin/estop.js on     # every call on this machine is denied immediately
node bin/estop.js off
```

## 8. Check the audit log

Every decision is written to an audit file in the folder named by `audit_dir` in the policy (default: `audit` next to the policy). To check that no line was changed or removed:

```bash
node bin/verify-audit.js path/to/audit/*.jsonl
```

## 9. Day to day

1. Plug in the stick.
2. Start `node bin/approve.js` and enter the password.
3. Let the agent work. Answer requests with `y` or `n`.
4. When you leave, stop `approve.js` and take the stick with you. Calls that need a human are then denied after the deadline; everything else continues within the policy.

## 10. When something does not work

| Message | Meaning | What to do |
|---|---|---|
| `private key not found: ...` | The stick is not plugged in, or mounted under a different name. | Plug it in. Check with `ls /media/$USER/`. |
| `Wrong password` | The password does not open the key file. | Try again. There is no reset, see below. |
| `no approval for this policy` | The policy was never signed. | `node bin/sign-policy.js <policy>` |
| `policy was changed after approval` | The policy file differs from what you signed. | Review the change, then sign again. |
| `approval expired` | The validity period is over. | Sign again. |
| `approval was made with a different key` | The policy was signed with another key pair. | Sign again with the current key. |
| `answer is not signed with the approval key` | The answer file carries no valid signature. `approve.js` writes such a file itself when you answer `n` while the stick is unplugged; the call is denied either way. | If you did not do that, find out what else wrote into `~/.sealgate/approvals`. |
| `at most N calls in ... seconds` | A rate limit from the policy was reached. | Wait, or change the policy and sign again. |
| `counter is locked by another gateway` | A gateway held the counter lock for more than 5 seconds. | Check for a hanging gateway process. |
| `emergency stop is set` | `ESTOP` exists. | `node bin/estop.js off` |

**Lost stick or forgotten password.** Neither can be recovered. If you have a backup of the key file, use it. Otherwise start over:

```bash
rm -f ~/.sealgate/public_key.pem ~/.sealgate/key_location
node bin/keygen.js --key-file /media/$USER/STICK/sealgate_key.pem
```

Then sign every policy again. Old approvals stop working, because they were made with the old key.

**What is in `~/.sealgate`.** `public_key.pem`, the private key unless it is on a stick, `key_location` (where the private key is), the serial number of the last approval, the emergency stop, pending and decided approvals, and the counters for rate limits and sums. No tool of the agent can reach this folder through SealGate. Do not put it on a network drive.
