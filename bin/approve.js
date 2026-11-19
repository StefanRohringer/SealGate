#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// approve.js: the human decides on calls that need approval by policy (for example orders above a limit).
// Runs in its own terminal and waits for new requests.
const fs = require('fs')
const path = require('path')
const readline = require('readline')
const K = require('../src/keys')

const pending = path.join(K.APPROVALS, 'pending')
const decided = path.join(K.APPROVALS, 'decided')
fs.mkdirSync(pending, { recursive: true, mode: 0o700 }); fs.mkdirSync(decided, { recursive: true, mode: 0o700 })
const ask = (q) => new Promise(r => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, a => { rl.close(); r(a) }) })
const seen = new Set()

async function main () {
  console.log('Waiting for requests that need approval. Stop with Ctrl+C.')
  for (;;) {
    for (const f of fs.readdirSync(pending).filter(f => f.endsWith('.json')).sort()) {
      if (seen.has(f)) continue
      seen.add(f)
      let r
      try { r = JSON.parse(fs.readFileSync(path.join(pending, f), 'utf8')) } catch { continue }
      console.log(`\n\x1b[33mRequest\x1b[0m  ${r.time}  policy "${r.policy}"`)
      console.log(`  tool: ${r.tool}`)
      for (const [k, v] of Object.entries(r.input || {})) console.log(`  ${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
      console.log(`  deadline: ${r.deadline}`)
      const answer = (await ask('Execute? (y/n): ')).trim().toLowerCase()
      if (!fs.existsSync(path.join(pending, f))) { console.log('Too late, the deadline has passed.'); continue }
      const yes = answer === 'y' || answer === 'yes'
      const reason = yes ? '' : (await ask('Reason (optional): ')).trim()
      fs.writeFileSync(path.join(decided, f), JSON.stringify({ id: r.id, decision: yes ? 'yes' : 'no', reason, by: process.env.USER || 'human', time: new Date().toISOString() }), { mode: 0o600 })
      console.log(yes ? '\x1b[32mApproved.\x1b[0m' : '\x1b[31mRejected.\x1b[0m')
    }
    await new Promise(r => setTimeout(r, 500))
  }
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
