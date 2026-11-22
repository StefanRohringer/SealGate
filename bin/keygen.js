#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// keygen.js: create the Ed25519 key pair for approvals once. The private key is encrypted with your
// password (AES-256). The public key always stays in ~/.sealgate, the gateway needs only that one.
//
//   node bin/keygen.js                                  private key in ~/.sealgate
//   node bin/keygen.js --key-file /media/you/STICK/sealgate_key.pem
//                                                       private key on a USB stick: without the stick
//                                                       nobody can approve a call or sign a policy
//   node bin/keygen.js --move-to /media/you/STICK/sealgate_key.pem
//                                                       move an existing private key onto a stick
const K = require('../src/keys')

const arg = (n) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : null }

async function main () {
  const moveTo = arg('move-to')
  if (process.argv.includes('--move-to')) {
    if (!moveTo) { console.log('usage: node bin/keygen.js --move-to <file>'); process.exit(1) }
    const m = K.moveKey(moveTo)
    console.log(`Private key moved: ${m.from} -> ${m.to}`)
    console.log('The old file was deleted. Deleting does not wipe a disk: if that matters to you, create a new key on the stick instead.')
    console.log('Keep a backup of the key file somewhere safe. Without it and the password there are no new approvals.')
    return
  }
  const keyFile = arg('key-file')
  if (process.argv.includes('--key-file') && !keyFile) { console.log('usage: node bin/keygen.js --key-file <file>'); process.exit(1) }
  K.checkCanCreate(keyFile)
  const p1 = await K.askHidden('New password for approvals (at least 12 characters): ')
  if (p1.length < 12) { console.log('Too short.'); process.exit(1) }
  if (p1 !== await K.askHidden('Repeat password: ')) { console.log('Passwords do not match.'); process.exit(1) }
  const r = K.createKeyPair(p1, keyFile)
  console.log(`Key pair created. Private key: ${r.file}. Public key: ${K.PUBLIC_KEY}. Key id: ${r.keyId}`)
  console.log('Keep a backup of the private key. Without it and the password there are no new approvals.')
}
main().catch(e => { console.error('error:', e.message); process.exit(1) })
