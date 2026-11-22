// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// counter.test.js: rate limits and rolling sums must survive a gateway restart.
// Replays the gateway's steps 5 to 7 with the real demo policy. Needs no MCP packages.
// Run: node test/counter.test.js

const fs = require('fs')
const os = require('os')
const path = require('path')
const G = require('../src/gates')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-counter-'))
const policy = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples', 'acme', 'acme.policy.json'), 'utf8'))
const rule = policy.tools.place_order

let passed = 0; let total = 0
function expect (title, actual, wanted) {
  total++
  const ok = actual === wanted
  if (ok) passed++
  console.log(`${ok ? '\x1b[32m ok \x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${title.padEnd(58)} ${actual}${ok ? '' : `  (expected ${wanted})`}`)
}

// One tool call the way gateway.js decides it (without input checks and without the real human).
function call (counter, input) {
  for (const [key, limit] of [['place_order', rule.rate_limit], ['*', policy.global_rate_limit]]) {
    const r = counter.check(key, limit)
    if (!r.ok) return 'denied [rate]'
  }
  const h = rule.human_approval
  const sumKey = 'place_order:without_human'
  if (G.needsHuman(rule, input, counter.sum(sumKey, h.rolling_sum_seconds))) return 'human'
  try { counter.record('place_order'); counter.record('*'); counter.add(sumKey, input.price_eur) } catch { return 'denied [rate]' }
  return 'executed'
}
const order = (price) => ({ item: 'PA6 pellets', quantity_kg: 160, price_eur: price })

console.log('\nIn memory (no file): unchanged behaviour')
const mem = new G.Counter()
expect('first order of 496 EUR passes', call(mem, order(496)), 'executed')
expect('second order of 496 EUR needs a human', call(mem, order(496)), 'human')

console.log('\nRolling sum across restarts')
const sumFile = path.join(TMP, 'counters', 'sum.json')
expect('restart 1: order of 496 EUR passes', call(new G.Counter(sumFile), order(496)), 'executed')
expect('restart 2: order of 496 EUR needs a human', call(new G.Counter(sumFile), order(496)), 'human')
expect('restart 3: order of 496 EUR needs a human', call(new G.Counter(sumFile), order(496)), 'human')
expect('restart 4: order of 3 EUR still passes (sum 499)', call(new G.Counter(sumFile), order(3)), 'executed')
expect('restart 5: order of 1 EUR needs a human (sum 500)', call(new G.Counter(sumFile), order(1)), 'human')

console.log('\nRate limit across restarts')
const rateFile = path.join(TMP, 'counters', 'rate.json')
for (let i = 1; i <= 3; i++) expect(`restart ${i}: order ${i} of the day passes`, call(new G.Counter(rateFile), order(75)), 'executed')
expect('restart 4: fourth order of the day is blocked', call(new G.Counter(rateFile), order(75)), 'denied [rate]')

console.log('\nTwo gateways with the same policy share the counters')
const sharedFile = path.join(TMP, 'counters', 'shared.json')
const a = new G.Counter(sharedFile); const b = new G.Counter(sharedFile)
expect('gateway A: order of 496 EUR passes', call(a, order(496)), 'executed')
expect('gateway B: order of 496 EUR needs a human', call(b, order(496)), 'human')

console.log('\nOld entries expire')
const old = new G.Counter(path.join(TMP, 'counters', 'old.json'))
old.add('place_order:without_human', 496, Date.now() - 90000 * 1000)
expect('an order from 25 hours ago no longer counts', call(new G.Counter(old.file), order(496)), 'executed')

console.log('\nFail closed')
const badFile = path.join(TMP, 'counters', 'bad.json')
fs.writeFileSync(badFile, '{ damaged')
expect('damaged counter file: call is denied', call(new G.Counter(badFile), order(75)), 'denied [rate]')
expect('damaged counter file: reading tools are denied too', String(new G.Counter(badFile).check('read_file', undefined).ok), 'false')
expect('counter file is private (mode 600)', (fs.statSync(sumFile).mode & 0o777).toString(8), '600')

console.log(`\n${passed} of ${total} checks passed.`)
fs.rmSync(TMP, { recursive: true, force: true })
process.exit(passed === total ? 0 : 1)
