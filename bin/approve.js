#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// approve.js: the human decides on calls that need approval by policy (for example orders above a limit).
// Runs in its own terminal and waits for new requests. Every decision is signed with your approval key.
// The gateway accepts no unsigned yes.
//
// The key is read fresh from its file for every decision and not kept. If it lives on a USB stick
// (see bin/keygen.js), approving works only while the stick is plugged in.
//
//   node bin/approve.js                     password once at the start
//   node bin/approve.js --ask-every-time    password for every single decision
const fs = require('fs')
const path = require('path')
const readline = require('readline')
const K = require('../src/keys')
const { signDecision } = require('../src/approval')

const pending = path.join(K.APPROVALS, 'pending')
const decided = path.join(K.APPROVALS, 'decided')
fs.mkdirSync(pending, { recursive: true, mode: 0o700 }); fs.mkdirSync(decided, { recursive: true, mode: 0o700 })
const ask = (q) => new Promise(r => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, a => { rl.close(); r(a) }) })
const seen = new Set()
const EVERY = process.argv.includes('--ask-every-time')
const by = process.env.USER || 'human'
let sessionPassword = null

// Sign one decision. Returns the signed answer, or null if no signed answer could be made.
// A missing key (stick unplugged) can be fixed by plugging it in, as long as the request is still open.
async function sign (file, request, decision, reason) {
  for (;;) {
    const password = EVERY ? await K.askHidden('Password: ') : sessionPassword
    try {
      return signDecision(request, decision, K.loadPrivateKey(password), { by, reason })
    } catch (e) {
      if (decision === 'no') return null // an unsigned no is still a no for the gateway
      if (!fs.existsSync(path.join(pending, file))) return null
      if (e.code === 'KEY_MISSING') {
        const a = (await ask(`\x1b[31m${e.message}\x1b[0m\nPlug in the stick and press Enter, or type n to reject: `)).trim().toLowerCase()
        if (a === 'n' || a === 'no') return null
      } else if (EVERY) {
        console.log('Wrong password, try again.')
      } else {
        console.log('The key no longer matches the password from the start. Restart approve.js.')
        return null
      }
    }
  }
}

async function main () {
  if (!EVERY) {
    sessionPassword = await K.askHidden('Password for approvals: ')
    try { K.loadPrivateKey(sessionPassword) } catch (e) {
      console.log(e.code === 'KEY_MISSING' ? `${e.message}. If it is on a stick, plug it in. If you have no key yet: node bin/keygen.js` : 'Wrong password.')
      process.exit(1)
    }
  }
  console.log(`Waiting for requests that need approval. Key: ${K.PRIVATE_KEY}. Stop with Ctrl+C.`)
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
      const signed = await sign(f, r, yes ? 'yes' : 'no', reason)
      if (!fs.existsSync(path.join(pending, f))) { console.log('Too late, the deadline has passed.'); continue }
      const out = signed || { id: r.id, decision: 'no', reason: reason || 'not signed', by, unsigned: true }
      fs.writeFileSync(path.join(decided, f + '.tmp'), JSON.stringify(out), { mode: 0o600 })
      fs.renameSync(path.join(decided, f + '.tmp'), path.join(decided, f))
      console.log(yes && signed ? '\x1b[32mApproved and signed.\x1b[0m' : '\x1b[31mRejected.\x1b[0m')
    }
    await new Promise(r => setTimeout(r, 500))
  }
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
