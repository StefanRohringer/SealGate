#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// sign-policy.js: a human reviews a policy and signs it with the private key (Ed25519).
// The approval contains the policy hash, an increasing serial number and an expiry date.
// If anyone changes a single character of the policy afterwards, the gateway denies everything.
// Usage: node bin/sign-policy.js <policy.json> [days valid, default 7] [name]
const fs = require('fs')
const readline = require('readline')
const K = require('../src/keys')
const { sha256 } = require('../src/gates')
const { signPolicy, approvalFileFor } = require('../src/approval')

const ask = (q) => new Promise(r => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, a => { rl.close(); r(a) }) })

async function main () {
  const file = process.argv[2]
  if (!file) { console.log('usage: node bin/sign-policy.js <policy.json> [days] [name]'); process.exit(1) }
  if (!fs.existsSync(K.PRIVATE_KEY)) { console.log(`Private key not found: ${K.PRIVATE_KEY}. If it is on a stick, plug it in. If you have no key yet: node bin/keygen.js`); process.exit(1) }
  const p = JSON.parse(fs.readFileSync(file, 'utf8'))
  const days = Number(process.argv[3] || 7)
  console.log(`Policy:      ${p.name}  (${p.description || ''})`)
  console.log(`Target:      ${p.target.command} ${(p.target.args || []).join(' ')}  in ${p.target.cwd || '.'}`)
  for (const [name, r] of Object.entries(p.tools)) {
    const checks = (r.checks || []).map(c => `${c.field} ${c.type}${c.values ? ' ' + JSON.stringify(c.values) : ''}${c.folders ? ' ' + JSON.stringify(c.folders) : ''}${c.min != null ? ' min ' + c.min : ''}${c.max != null ? ' max ' + c.max : ''}`).join('; ')
    console.log(`  ${name}: ${checks || 'no fields'}${r.rate_limit ? `  | at most ${r.rate_limit.count} per ${r.rate_limit.per_seconds} s` : ''}${r.human_approval ? '  | human approval' : ''}`)
  }
  console.log(`Global rate: ${p.global_rate_limit ? `${p.global_rate_limit.count} per ${p.global_rate_limit.per_seconds} s` : 'none'}`)
  console.log(`Hash:        ${sha256(p)}`)
  console.log(`Valid for:   ${days} days`)
  console.log('Every tool not listed here is blocked and hidden from the model.')
  if ((await ask('Approve this policy? Type "approve": ')).trim() !== 'approve') { console.log('Not approved.'); process.exit(1) }
  const password = await K.askHidden('Password: ')
  let key
  try { key = K.loadPrivateKey(password) } catch (e) { console.log(e.code === 'KEY_MISSING' ? `${e.message}. Nothing approved.` : 'Wrong password. Nothing approved.'); process.exit(1) }
  const d = signPolicy(file, key, { days, by: process.argv[4] || process.env.USER || 'unknown', serial: K.nextSerial() })
  console.log(`Approved: ${approvalFileFor(file)}  (serial ${d.serial}, valid until ${d.expires_at})`)
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
