#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// gateway.js: the SealGate gateway. An MCP server placed in front of any other MCP server.
//
//   model  -->  SealGate gateway  -->  real MCP server (files, email, ERP, ...)
//
// Principle: the model proposes, the gateway decides. When in doubt, deny (fail closed).
// For every tool call, in this order:
//   1. Emergency stop: if ~/.sealgate/ESTOP exists, everything is denied.
//   2. Policy:         the policy file must be signed by a human, unchanged and not expired.
//   3. Tool:           only tools named in the policy. Other tools are hidden from the model.
//   4. Input:          every field is checked, unknown fields are denied.
//   5. Rate:           maximum calls per time window, per tool and in total (kept on disk, survives restarts).
//   6. Human:          where the policy says so, a human must approve (bin/approve.js).
//   7. Execute, then redact secrets in the response.
// Every decision is written to a hash-chained audit log.
//
// Usage (from an MCP client): node src/gateway.js <policy.json>

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { Server } = require('@modelcontextprotocol/sdk/server/index.js')
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js')
const { Client } = require('@modelcontextprotocol/sdk/client/index.js')
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js')
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js')
const G = require('./gates')
const K = require('./keys')
const { verifyApproval } = require('./approval')
const { AuditLog } = require('./audit')

const log = (...a) => process.stderr.write('[sealgate] ' + a.join(' ') + '\n') // stdout belongs to MCP
const sleep = ms => new Promise(r => setTimeout(r, ms))

if (!process.argv[2]) { log('usage: node src/gateway.js <policy.json>'); process.exit(1) }
const POLICY_FILE = path.resolve(process.argv[2])
const READ_POLICY = 'sealgate_read_policy'

async function main () {
  const start = verifyApproval(POLICY_FILE)
  if (!start.ok) { log(`refusing to start: ${start.reason}. First run: node bin/sign-policy.js ${process.argv[2]}`); process.exit(1) }
  const policyDir = start.policyDir
  const target = start.policy.target
  const targetKey = G.canonical(target)
  const targetDir = path.resolve(policyDir, target.cwd || '.')
  const audit = new AuditLog(path.resolve(policyDir, start.policy.audit_dir || 'audit'),
    `${start.policy.name}_${new Date().toISOString().replace(/[:.]/g, '-')}`)
  audit.write({ event: 'start', policy: start.policy.name, serial: start.doc.serial, expires_at: start.doc.expires_at })
  log(`policy "${start.policy.name}" approved (serial ${start.doc.serial}). Audit log: ${audit.file}`)

  // Start the real MCP server with a minimal environment: it does not inherit the caller's API keys.
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: process.env.LANG || 'C.UTF-8', ...(target.env || {}) }
  const transport = new StdioClientTransport({
    command: target.command === 'node' ? process.execPath : target.command,
    args: target.args || [], cwd: targetDir, env, stderr: 'pipe'
  })
  if (transport.stderr) transport.stderr.on('data', d => process.stderr.write(d))
  const client = new Client({ name: 'sealgate-gateway', version: '0.2.0' })
  await client.connect(transport)

  // Counters are kept on disk in the protected SealGate directory, so limits survive a restart.
  const counter = new G.Counter(path.join(K.DIR, 'counters', String(start.policy.name).replace(/[^A-Za-z0-9_.-]/g, '_') + '.json'))
  const ctx = { policyDir, targetDir, protected: [K.DIR] }

  const denied = (tool, input, gate, reason) => {
    audit.write({ tool, input: trim(input), verdict: 'denied', gate, reason })
    log(`denied: ${tool} [${gate}] ${reason}`)
    return { content: [{ type: 'text', text: JSON.stringify({ result: 'denied', gate, reason }) }], isError: true }
  }

  const server = new Server({ name: 'sealgate', version: '0.2.0' }, { capabilities: { tools: {} } })

  // Tool list: only approved tools, with the note from the policy.
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const v = verifyApproval(POLICY_FILE)
    const own = { name: READ_POLICY, description: 'Shows which tools are approved and which rules apply to them.', inputSchema: { type: 'object', properties: {} } }
    if (!v.ok) return { tools: [own] }
    const { tools } = await client.listTools()
    const visible = tools.filter(t => v.policy.tools[t.name]).map(t => {
      const note = v.policy.tools[t.name].note
      return { ...t, description: (t.description || '') + (note ? ` Rule: ${note}` : '') }
    })
    return { tools: [...visible, own] }
  })

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const tool = request.params.name
    const input = request.params.arguments || {}
    const began = Date.now()

    // 1. Emergency stop
    if (fs.existsSync(K.ESTOP)) return denied(tool, input, 'estop', 'emergency stop is set')

    // 2. Policy approval, read fresh from disk on every call
    const v = verifyApproval(POLICY_FILE)
    if (!v.ok) return denied(tool, input, 'policy', v.reason)
    if (G.canonical(v.policy.target) !== targetKey) return denied(tool, input, 'policy', 'target changed in the policy, restart the gateway')
    const policy = v.policy

    if (tool === READ_POLICY) {
      audit.write({ tool, verdict: 'read' })
      return { content: [{ type: 'text', text: JSON.stringify(policySummary(policy), null, 1) }] }
    }

    // 3. Tool approved?
    const rule = policy.tools[tool]
    if (!rule) return denied(tool, input, 'tool', 'tool is not approved')

    // 4. Input
    const c = G.checkInput(rule, input, ctx)
    if (!c.ok) return denied(tool, input, c.gate, c.reason)

    // 5. Rate
    for (const [key, limit] of [[tool, rule.rate_limit], ['*', policy.global_rate_limit]]) {
      const r = counter.check(key, limit)
      if (!r.ok) return denied(tool, input, 'rate', r.reason)
    }

    // 6. Human (with rolling_sum_seconds, what already passed without a human counts too)
    const h = rule.human_approval
    const sumKey = `${tool}:without_human`
    const sofar = h && h.rolling_sum_seconds ? counter.sum(sumKey, h.rolling_sum_seconds) : 0
    const withHuman = G.needsHuman(rule, input, sofar)
    if (withHuman) {
      const a = await askHuman(policy, tool, { ...input, ...(sofar ? { _sum_without_approval: sofar } : {}) })
      if (!a.ok) return denied(tool, input, 'human', a.reason)
      audit.write({ tool, input: trim(input), verdict: 'approved', by: a.by, sum_without_approval: sofar })
    }

    // 7. Execute
    try {
      counter.record(tool); counter.record('*')
      if (h && h.rolling_sum_seconds && !withHuman) { const f = G.getField(input, h.field); if (f.present && typeof f.value === 'number') counter.add(sumKey, f.value) }
    } catch (err) { return denied(tool, input, 'rate', `counter state cannot be saved: ${err.message}`) }
    let result
    try {
      result = await client.callTool({ name: tool, arguments: input }, undefined, { timeout: (rule.timeout_s || 60) * 1000 })
    } catch (err) {
      audit.write({ tool, input: trim(input), verdict: 'error', reason: err.message })
      return { content: [{ type: 'text', text: JSON.stringify({ result: 'error', reason: err.message }) }], isError: true }
    }

    // Response: redact secrets and limit length before the model sees it
    let redacted = 0
    const content = (result.content || []).map(item => {
      if (item.type !== 'text') return policy.text_only_responses === false ? item : { type: 'text', text: `[${item.type} removed]` }
      const r = G.redact(item.text, policy.redact)
      redacted += r.count
      const max = policy.max_response_chars || 20000
      return { type: 'text', text: r.text.length > max ? r.text.slice(0, max) + `\n[truncated to ${max} characters]` : r.text }
    })
    audit.write({ tool, input: trim(input), verdict: result.isError ? 'target_error' : 'executed', redacted, ms: Date.now() - began })
    return { ...result, content }
  })

  await server.connect(new StdioServerTransport())
  log('gateway ready.')
}

// Human approval: request in ~/.sealgate/approvals/pending, answer in .../decided.
async function askHuman (policy, tool, input) {
  const pending = path.join(K.APPROVALS, 'pending')
  const decided = path.join(K.APPROVALS, 'decided')
  fs.mkdirSync(pending, { recursive: true, mode: 0o700 }); fs.mkdirSync(decided, { recursive: true, mode: 0o700 })
  const id = crypto.randomUUID()
  const timeout = (policy.human_approval_timeout_s || 120) * 1000
  const req = { id, policy: policy.name, tool, input, time: new Date().toISOString(), deadline: new Date(Date.now() + timeout).toISOString() }
  fs.writeFileSync(path.join(pending, `${id}.json`), JSON.stringify(req, null, 2), { mode: 0o600 })
  log(`human approval needed for ${tool}. In a terminal: node bin/approve.js`)
  const end = Date.now() + timeout
  const answerFile = path.join(decided, `${id}.json`)
  try {
    while (Date.now() < end) {
      if (fs.existsSync(answerFile)) {
        let a = {}
        try { a = JSON.parse(fs.readFileSync(answerFile, 'utf8')) } catch {}
        if (a.id !== id) return { ok: false, reason: 'answer does not match the request' }
        return a.decision === 'yes' ? { ok: true, by: a.by || 'human' } : { ok: false, reason: `rejected by a human${a.reason ? ': ' + a.reason : ''}` }
      }
      await sleep(400)
    }
    return { ok: false, reason: `no answer from a human within ${timeout / 1000} seconds` }
  } finally {
    try { fs.unlinkSync(path.join(pending, `${id}.json`)) } catch {}
  }
}

function policySummary (policy) {
  const tools = {}
  for (const [name, r] of Object.entries(policy.tools)) {
    tools[name] = {
      note: r.note || '',
      checks: (r.checks || []).map(c => ({ field: c.field, type: c.type, ...(c.values ? { values: c.values } : {}), ...(c.min != null ? { min: c.min } : {}), ...(c.max != null ? { max: c.max } : {}), ...(c.folders ? { folders: c.folders } : {}) })),
      rate_limit: r.rate_limit || null,
      human_approval: r.human_approval || false
    }
  }
  return { policy: policy.name, description: policy.description || '', tools, global_rate_limit: policy.global_rate_limit || null }
}

// Shorten long values in the audit log so it stays readable.
function trim (v, depth = 0) {
  if (typeof v === 'string') return v.length > 300 ? v.slice(0, 300) + `... (${v.length} chars)` : v
  if (Array.isArray(v)) return depth > 3 ? '[...]' : v.slice(0, 20).map(x => trim(x, depth + 1))
  if (v && typeof v === 'object') { if (depth > 3) return '{...}'; const o = {}; for (const k of Object.keys(v).slice(0, 30)) o[k] = trim(v[k], depth + 1); return o }
  return v
}

main().catch(e => { log('error:', e.message); process.exit(1) })
