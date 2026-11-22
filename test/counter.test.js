// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// counter.test.js: rate limits and rolling sums must survive a gateway restart and must hold when several
// gateways decide at the same instant.
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

// ---- Several gateways at the same instant (real processes) ----
// Each worker is one gateway deciding one order the way gateway.js does: one locked transaction that
// checks the rate limit, looks at the rolling sum and books the call if no human is needed.
const { spawn, spawnSync } = require('child_process')
const WORKER = `
const G = require(process.argv[1]); const policy = require(process.argv[2]); const rule = policy.tools.place_order
const input = { item: 'PA6 pellets', quantity_kg: 160, price_eur: Number(process.argv[5]) }
const c = new G.Counter(process.argv[3])
const wait = Number(process.argv[4]) - Date.now(); if (wait > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, wait)
let out
try {
  out = c.transaction(c => {
    if (!c.check('place_order', rule.rate_limit).ok) return 'rate'
    if (G.needsHuman(rule, input, c.sum('place_order:without_human', rule.human_approval.rolling_sum_seconds))) return 'human'
    c.record('place_order'); c.add('place_order:without_human', input.price_eur)
    return 'executed'
  })
} catch (e) { out = 'error ' + e.message }
console.log(out)`
function gateways (n, file, price) {
  const start = Date.now() + 400 // all workers wait for the same instant
  return Promise.all(Array.from({ length: n }, () => new Promise(resolve => {
    let out = ''
    const p = spawn(process.execPath, ['-e', WORKER, path.join(__dirname, '..', 'src', 'gates.js'), path.join(__dirname, '..', 'examples', 'acme', 'acme.policy.json'), file, String(start), String(price)])
    p.stdout.on('data', d => { out += d }); p.on('close', () => resolve(out.trim()))
  })))
}
const count = (list, what) => list.filter(x => x === what).length

async function concurrent () {
  console.log('\nEight gateways decide at the same instant')
  let worstSum = 0; let worstRate = 0; let other = 0
  for (let round = 1; round <= 5; round++) {
    const a = await gateways(8, path.join(TMP, 'counters', `race-sum-${round}.json`), 496)
    worstSum = Math.max(worstSum, count(a, 'executed')); other += a.length - count(a, 'executed') - count(a, 'human')
    const b = await gateways(8, path.join(TMP, 'counters', `race-rate-${round}.json`), 75)
    worstRate = Math.max(worstRate, count(b, 'executed')); other += b.length - count(b, 'executed') - count(b, 'rate')
  }
  expect('orders of 496 EUR: at most one passes without a human', String(worstSum), '1')
  expect('orders of 75 EUR: at most three pass (rate limit)', String(worstRate), '3')
  expect('every other gateway got a clean answer (human or rate)', String(other), '0')

  console.log('\nThe lock itself')
  const lockTest = path.join(TMP, 'counters', 'lock.json')
  call(new G.Counter(lockTest), order(75))
  expect('no lock file is left behind', String(fs.existsSync(lockTest + '.lock')), 'false')
  fs.writeFileSync(lockTest + '.lock', String(spawnSync(process.execPath, ['-e', '']).pid)) // a gateway that died while holding the lock
  expect('lock of a dead gateway is taken over', call(new G.Counter(lockTest), order(75)), 'executed')
  fs.writeFileSync(lockTest + '.lock', String(process.pid)) // a live gateway that does not let go
  expect('lock held by a live gateway: call is denied', call(new G.Counter(lockTest, { lockWaitMs: 300 }), order(75)), 'denied [rate]')
  fs.unlinkSync(lockTest + '.lock')
  expect('lock released: works again', call(new G.Counter(lockTest), order(75)), 'executed')
}

concurrent().then(() => {
  console.log(`\n${passed} of ${total} checks passed.`)
  fs.rmSync(TMP, { recursive: true, force: true })
  process.exit(passed === total ? 0 : 1)
}).catch(e => { console.error('error:', e); process.exit(1) })
