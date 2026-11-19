#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// keygen.js: create the Ed25519 key pair for policy approvals once, in ~/.sealgate.
// The private key is encrypted with your password (AES-256).
const fs = require('fs')
const crypto = require('crypto')
const K = require('../src/keys')

async function main () {
  if (fs.existsSync(K.PRIVATE_KEY)) { console.log(`A key already exists: ${K.PRIVATE_KEY}. Nothing changed.`); process.exit(0) }
  const p1 = await K.askHidden('New password for approvals (at least 12 characters): ')
  if (p1.length < 12) { console.log('Too short.'); process.exit(1) }
  if (p1 !== await K.askHidden('Repeat password: ')) { console.log('Passwords do not match.'); process.exit(1) }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  fs.mkdirSync(K.DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(K.PRIVATE_KEY, privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: p1 }), { mode: 0o600 })
  fs.writeFileSync(K.PUBLIC_KEY, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 })
  console.log(`Key pair created in ${K.DIR}. Key id: ${K.fingerprint(publicKey)}`)
  console.log('Keep a backup of the private key. Without it and the password there are no new approvals.')
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
