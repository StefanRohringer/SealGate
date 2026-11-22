// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// approval.test.js: a human's decision on a single call counts only if it is signed with the approval key
// and belongs to exactly that request. Needs no MCP packages.
// Run: node test/approval.test.js

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-approval-'))
process.env.SEALGATE_DIR = TMP
const K = require('../src/keys')
const { signDecision, verifyDecision } = require('../src/approval')

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
fs.writeFileSync(K.PUBLIC_KEY, publicKey.export({ type: 'spki', format: 'pem' }))
const stranger = crypto.generateKeyPairSync('ed25519').privateKey

let passed = 0; let total = 0
function expect (title, actual, wanted) {
  total++
  const ok = actual === wanted
  if (ok) passed++
  console.log(`${ok ? '\x1b[32m ok \x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${title.padEnd(58)} ${actual}${ok ? '' : `  (expected ${wanted})`}`)
}
const request = (id, price) => ({ id, policy: 'acme-demo', tool: 'place_order', input: { item: 'PA6 pellets', quantity_kg: 200, price_eur: price }, time: '2026-11-22T20:00:00.000Z', deadline: '2026-11-22T20:02:00.000Z' })
const verdict = (req, answer) => { const v = verifyDecision(req, answer); return v.ok ? `approved by ${v.by}` : v.reason }
const copy = (x) => JSON.parse(JSON.stringify(x))

const r1 = request('11111111-aaaa', 620)
const r2 = request('22222222-bbbb', 620)
const yes = signDecision(r1, 'yes', privateKey, { by: 'stefan' })

console.log('\nSigned decisions')
expect('signed yes for this request', verdict(r1, copy(yes)), 'approved by stefan')
expect('signed no with a reason', verdict(r1, signDecision(r1, 'no', privateKey, { reason: 'too expensive' })), 'rejected by a human: too expensive')

console.log('\nForged approvals')
expect('plain yes without signature (old format)', verdict(r1, { id: r1.id, decision: 'yes', by: 'someone' }), 'answer is not signed with the approval key')
expect('empty or unreadable answer', verdict(r1, null), 'answer is not signed with the approval key')
expect('yes signed with a foreign key', verdict(r1, signDecision(r1, 'yes', stranger)), 'signature of the answer is invalid')
expect('signed yes reused for another request', verdict(r2, copy(yes)), 'answer does not match the request')
expect('signed yes, request changed afterwards (price)', verdict(request('11111111-aaaa', 4900), copy(yes)), 'answer does not match the request')
const flipped = signDecision(r1, 'no', privateKey); flipped.document.decision = 'yes'
expect('signed no edited into a yes', verdict(r1, flipped), 'signature of the answer is invalid')
const renamed = copy(yes); renamed.document.id = r2.id
expect('signed yes with the id edited', verdict(r2, renamed), 'signature of the answer is invalid')
expect('a signed policy approval is not a call approval', verdict(r1, (() => { const d = { kind: 'policy_approval', id: r1.id }; return { document: d, signature: crypto.sign(null, Buffer.from(require('../src/gates').canonical(d)), privateKey).toString('base64') } })()), 'wrong kind of answer')

console.log(`\n${passed} of ${total} checks passed.`)
fs.rmSync(TMP, { recursive: true, force: true })
process.exit(passed === total ? 0 : 1)
