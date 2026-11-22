// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// keyfile.test.js: the private key may live outside ~/.sealgate, for example on a USB stick.
// While the "stick" is gone, nothing can be signed. A folder stands in for the stick. Needs no MCP packages.
// Run: node test/keyfile.test.js

const fs = require('fs')
const os = require('os')
const path = require('path')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-keyfile-'))
process.env.SEALGATE_DIR = path.join(TMP, 'sealgate')
delete process.env.SEALGATE_KEY_FILE
const K = require('../src/keys')
const G = require('../src/gates')
const { signDecision, verifyDecision } = require('../src/approval')

let passed = 0; let total = 0
function expect (title, actual, wanted) {
  total++
  const ok = actual === wanted
  if (ok) passed++
  console.log(`${ok ? '\x1b[32m ok \x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${title.padEnd(58)} ${actual}${ok ? '' : `  (expected ${wanted})`}`)
}
const code = (fn) => { try { fn(); return 'ok' } catch (e) { return e.code || e.message } }
const STICK = path.join(TMP, 'stick')
const AWAY = path.join(TMP, 'stick-unplugged')
const KEYFILE = path.join(STICK, 'sealgate_key.pem')
const PASSWORD = 'correct horse battery'
const request = { id: 'aaaa-1111', policy: 'acme-demo', tool: 'place_order', input: { item: 'PA6 pellets', quantity_kg: 200, price_eur: 620 }, time: '2026-11-22T20:00:00.000Z', deadline: '2026-11-22T20:02:00.000Z' }
const approve = () => { const v = verifyDecision(request, signDecision(request, 'yes', K.loadPrivateKey(PASSWORD), { by: 'stefan' })); return v.ok ? 'approved' : v.reason }

console.log('\nKey on the stick')
fs.mkdirSync(STICK)
const made = K.createKeyPair(PASSWORD, KEYFILE)
expect('private key is written to the stick', String(made.file === KEYFILE && fs.existsSync(KEYFILE)), 'true')
expect('private key is encrypted', String(fs.readFileSync(KEYFILE, 'utf8').includes('ENCRYPTED PRIVATE KEY')), 'true')
expect('no private key in the SealGate directory', String(fs.readdirSync(K.DIR).some(f => f.includes('private'))), 'false')
expect('public key stays in the SealGate directory', String(fs.existsSync(K.PUBLIC_KEY)), 'true')
expect('location is remembered', K.privateKeyFile(), KEYFILE)
expect('stick plugged in: decision is signed and accepted', approve(), 'approved')
expect('wrong password', code(() => K.loadPrivateKey('wrong password 123')), 'WRONG_PASSWORD')

console.log('\nStick unplugged')
fs.renameSync(STICK, AWAY)
expect('signing fails, key is missing', code(approve), 'KEY_MISSING')
expect('a second key pair is refused', String(code(() => K.createKeyPair(PASSWORD)).startsWith('a public key already exists')), 'true')
fs.renameSync(AWAY, STICK)
expect('stick plugged in again: signing works', approve(), 'approved')

console.log('\nLocation')
process.env.SEALGATE_KEY_FILE = path.join(TMP, 'elsewhere.pem')
expect('SEALGATE_KEY_FILE overrides the remembered location', K.privateKeyFile(), path.join(TMP, 'elsewhere.pem'))
delete process.env.SEALGATE_KEY_FILE
expect('K.PRIVATE_KEY follows the current location', K.PRIVATE_KEY, KEYFILE)
const ctx = { policyDir: TMP, targetDir: TMP, protected: [K.DIR, K.privateKeyFile()] }
expect('agent tool cannot read the key file, even in an allowed folder', String(G.CHECKS.path_within(KEYFILE, { folders: ['stick'] }, ctx)), 'path points to a protected SealGate location (keys, approvals, emergency stop)')
expect('other files in that folder stay reachable', String(G.CHECKS.path_within(path.join(STICK, 'notes.txt'), { folders: ['stick'] }, ctx)), 'null')

console.log('\nMove an existing key to a stick')
const TMP2 = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-keyfile2-'))
fs.rmSync(K.DIR, { recursive: true, force: true })
K.createKeyPair(PASSWORD)
const local = K.privateKeyFile()
expect('default: private key in the SealGate directory', String(local === path.join(K.DIR, 'private_key.pem') && fs.existsSync(local)), 'true')
const target = path.join(TMP2, 'stick', 'key.pem')
K.moveKey(target)
expect('after the move: key is on the stick', String(fs.existsSync(target) && K.privateKeyFile() === target), 'true')
expect('after the move: gone from the SealGate directory', String(fs.existsSync(local)), 'false')
expect('moved key still signs', approve(), 'approved')
expect('moving onto an existing file is refused', String(code(() => K.moveKey(target)).startsWith('the key is already there')), 'true')

console.log(`\n${passed} of ${total} checks passed.`)
fs.rmSync(TMP, { recursive: true, force: true }); fs.rmSync(TMP2, { recursive: true, force: true })
process.exit(passed === total ? 0 : 1)
