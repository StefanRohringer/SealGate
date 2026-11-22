// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// keys.js: locations and helpers for the approval key (Node built-ins only).
// Everything lives in ~/.sealgate (override with SEALGATE_DIR): keys, emergency stop,
// pending human approvals and the highest serial seen. Agent tools must never reach this directory.
// The private key alone may live somewhere else, for example on a USB stick (see privateKeyFile).

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const DIR = process.env.SEALGATE_DIR || path.join(os.homedir(), '.sealgate')
const DEFAULT_PRIVATE_KEY = path.join(DIR, 'private_key.pem')
const KEY_LOCATION = path.join(DIR, 'key_location')
const PUBLIC_KEY = path.join(DIR, 'public_key.pem')
const SERIAL = path.join(DIR, 'serial')
const STATE = path.join(DIR, 'gateway_state.json')
const ESTOP = path.join(DIR, 'ESTOP')
const APPROVALS = path.join(DIR, 'approvals')

function fingerprint (publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' })
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16)
}
const loadPublicKey = () => crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY))

// Where the private key lives. Default: private_key.pem in the SealGate directory. To keep it on a USB stick,
// set SEALGATE_KEY_FILE or let bin/keygen.js record the path in ~/.sealgate/key_location.
// Looked up on every call, so a changed location is picked up without a restart.
function privateKeyFile () {
  if (process.env.SEALGATE_KEY_FILE) return path.resolve(process.env.SEALGATE_KEY_FILE)
  try { const p = fs.readFileSync(KEY_LOCATION, 'utf8').trim(); if (p) return path.resolve(p) } catch {}
  return DEFAULT_PRIVATE_KEY
}

// Read the private key fresh from its file. Nothing is cached: if the key is on a stick and the stick is
// unplugged, this fails with code KEY_MISSING. A wrong password fails with code WRONG_PASSWORD.
function loadPrivateKey (password) {
  const file = privateKeyFile()
  let pem
  try { pem = fs.readFileSync(file) } catch { const e = new Error(`private key not found: ${file}`); e.code = 'KEY_MISSING'; throw e }
  try { return crypto.createPrivateKey({ key: pem, passphrase: password }) } catch { const e = new Error('wrong password or damaged key'); e.code = 'WRONG_PASSWORD'; throw e }
}

// Create the key pair. The public key always goes to the SealGate directory (the gateway needs only that one).
// The private key goes to keyFile if given (for example a file on a USB stick), otherwise next to it.
function createKeyPair (password, keyFile) {
  const target = keyFile ? path.resolve(keyFile) : DEFAULT_PRIVATE_KEY
  if (fs.existsSync(PUBLIC_KEY)) throw new Error(`a public key already exists: ${PUBLIC_KEY}. If your private key is on a stick, plug it in. To start over, delete that file first`)
  if (fs.existsSync(target)) throw new Error(`a private key already exists: ${target}`)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 })
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: password }), { mode: 0o600, flag: 'wx' })
  fs.writeFileSync(PUBLIC_KEY, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 })
  if (keyFile) fs.writeFileSync(KEY_LOCATION, target + '\n', { mode: 0o600 })
  else { try { fs.unlinkSync(KEY_LOCATION) } catch {} }
  return { file: target, keyId: fingerprint(publicKey) }
}

// Move an existing private key to another place (for example onto a USB stick) and remember the new location.
function moveKey (keyFile) {
  const from = privateKeyFile()
  const to = path.resolve(keyFile)
  if (from === to) throw new Error('the key is already there')
  if (!fs.existsSync(from)) throw new Error(`private key not found: ${from}`)
  if (fs.existsSync(to)) throw new Error(`a file already exists: ${to}`)
  const pem = fs.readFileSync(from)
  fs.mkdirSync(path.dirname(to), { recursive: true })
  fs.writeFileSync(to, pem, { mode: 0o600, flag: 'wx' })
  if (!fs.readFileSync(to).equals(pem)) throw new Error('the copy differs from the original, nothing was removed')
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(KEY_LOCATION, to + '\n', { mode: 0o600 })
  fs.unlinkSync(from)
  return { from, to }
}

// Ask for a password without echoing it.
function askHidden (question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    if (!stdin.isTTY) return reject(new Error('password input needs a terminal'))
    process.stdout.write(question)
    let input = ''
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8')
    const onKey = (chars) => {
      for (const ch of chars) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onKey)
          process.stdout.write('\n')
          return resolve(input)
        }
        if (ch === '\u0003') { process.stdout.write('\n'); process.exit(1) }
        if (ch === '\u007f' || ch === '\b') { input = input.slice(0, -1); continue }
        input += ch
      }
    }
    stdin.on('data', onKey)
  })
}

function nextSerial () {
  let n = 0
  try { n = parseInt(fs.readFileSync(SERIAL, 'utf8'), 10) || 0 } catch {}
  n += 1
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(SERIAL, String(n) + '\n', { mode: 0o600 })
  return n
}

module.exports = { DIR, PUBLIC_KEY, KEY_LOCATION, STATE, ESTOP, APPROVALS, fingerprint, loadPublicKey, privateKeyFile, loadPrivateKey, createKeyPair, moveKey, askHidden, nextSerial }
// PRIVATE_KEY is the current location of the private key (see privateKeyFile).
Object.defineProperty(module.exports, 'PRIVATE_KEY', { enumerable: true, get: privateKeyFile })
