// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// keys.js: locations and helpers for the approval key (Node built-ins only).
// Everything lives in ~/.sealgate (override with SEALGATE_DIR): keys, emergency stop,
// pending human approvals and the highest serial seen. Agent tools must never reach this directory.

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const DIR = process.env.SEALGATE_DIR || path.join(os.homedir(), '.sealgate')
const PRIVATE_KEY = path.join(DIR, 'private_key.pem')
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

module.exports = { DIR, PRIVATE_KEY, PUBLIC_KEY, STATE, ESTOP, APPROVALS, fingerprint, loadPublicKey, askHidden, nextSerial }
