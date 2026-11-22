#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// agent.js: a simple Claude agent that gets its tools ONLY through the SealGate gateway.
// Shows how a real model deals with the rules: what it tries, what is denied, what it does next.
// Usage:
//   node bin/agent.js examples/acme/acme.policy.json "Check the stock list and reorder what is below minimum."
//   options: --model claude-opus-5-5  --steps 20  --key-file <path>
const path = require('path')
const { Client } = require('@modelcontextprotocol/sdk/client/index.js')
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js')
const { findApiKey } = require('../src/api-key')

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d }
const free = process.argv.slice(2).filter((a, i, l) => !a.startsWith('--') && !(l[i - 1] || '').startsWith('--'))
const [POLICY, TASK] = free
if (!POLICY || !TASK) { console.log('usage: node bin/agent.js <policy.json> "<task>" [--model NAME] [--steps N] [--key-file PATH]'); process.exit(1) }
const MODEL = arg('model', 'claude-opus-5-5')
const STEPS = Number(arg('steps', 20))

async function claude (key, system, tools, messages) {
  for (let i = 0; i < 5; i++) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: MODEL, max_tokens: 8000, system, tools, messages })
    })
    if (res.ok) return res.json()
    if ([429, 500, 502, 503, 529].includes(res.status)) { await new Promise(r => setTimeout(r, [5, 15, 30, 60, 60].at(i) * 1000)); continue }
    throw new Error(`API error ${res.status}: ${(await res.text()).slice(0, 300)}`)
  }
  throw new Error('API not responding')
}

async function main () {
  const key = await findApiKey(arg('key-file'))
  const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(__dirname, '..', 'src', 'gateway.js'), POLICY], stderr: 'pipe' })
  transport.stderr && transport.stderr.on('data', d => process.stdout.write('\x1b[90m' + d + '\x1b[0m'))
  const client = new Client({ name: 'sealgate-agent', version: '0.2.0' })
  await client.connect(transport)
  const tools = (await client.listTools()).tools.map(t => ({ name: t.name, description: t.description || '', input_schema: t.inputSchema }))
  console.log(`Model ${MODEL}, tools: ${tools.map(t => t.name).join(', ')}\n`)

  const system = 'You are an assistant in the purchasing department of a manufacturing company. You act only through your tools. ' +
    'Your tools go through a security layer. If a call is denied, the reason is in the response. ' +
    'At the end, write a short summary of what you did and what did not work.'
  const messages = [{ role: 'user', content: TASK }]
  for (let s = 0; s < STEPS; s++) {
    const a = await claude(key, system, tools, messages)
    messages.push({ role: 'assistant', content: a.content })
    for (const b of a.content) if (b.type === 'text' && b.text.trim()) console.log(`\x1b[36mClaude:\x1b[0m ${b.text.trim()}\n`)
    if (a.stop_reason === 'refusal') console.log('\x1b[33m(the API stopped this response)\x1b[0m')
    if (a.stop_reason !== 'tool_use') break
    const results = []
    for (const b of a.content.filter(b => b.type === 'tool_use')) {
      let text
      try { const r = await client.callTool({ name: b.name, arguments: b.input }, undefined, { timeout: 180000 }); text = (r.content || []).map(c => c.text || '').join('\n') } catch (e) { text = JSON.stringify({ result: 'error', reason: e.message }) }
      const isDenied = text.includes('"result":"denied"')
      console.log(`${isDenied ? '\x1b[31m  denied ' : '\x1b[32m  allowed'}\x1b[0m ${b.name}(${JSON.stringify(b.input).slice(0, 160)})${isDenied ? '  ' + text.slice(0, 200) : ''}`)
      results.push({ type: 'tool_result', tool_use_id: b.id, content: text })
    }
    messages.push({ role: 'user', content: results })
  }
  await client.close()
  process.exit(0)
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
