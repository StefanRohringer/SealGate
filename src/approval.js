// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// approval.js: is the policy signed by a human, unchanged and still valid?
// Checks the Ed25519 signature, the policy hash, the expiry date, the key fingerprint and the serial number
// (an approval older than the newest one seen is rejected, so nobody can replay an old approval).

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { canonical, sha256 } = require('./gates')
const K = require('./keys')

const approvalFileFor = (policyFile) => policyFile.replace(/\.json$/, '') + '.approval.json'

function readState () { try { return JSON.parse(fs.readFileSync(K.STATE, 'utf8')) } catch { return {} } }
function rememberSerial (name, serial) {
  const state = readState()
  if ((state[name] || 0) >= serial) return
  state[name] = serial
  fs.mkdirSync(K.DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(K.STATE, JSON.stringify(state, null, 2), { mode: 0o600 })
}

// Returns { ok, reason, policy, doc, policyDir }. Reads fresh from disk on every call.
function verifyApproval (policyFile, now = new Date()) {
  let policy, approval, publicKey
  try { policy = JSON.parse(fs.readFileSync(policyFile, 'utf8')) } catch (e) { return { ok: false, reason: `policy cannot be read: ${e.message}` } }
  try { approval = JSON.parse(fs.readFileSync(approvalFileFor(policyFile), 'utf8')) } catch { return { ok: false, reason: 'no approval for this policy' } }
  try { publicKey = K.loadPublicKey() } catch { return { ok: false, reason: 'public key missing' } }

  const d = approval && approval.document
  if (!d || typeof approval.signature !== 'string') return { ok: false, reason: 'approval incomplete' }
  let valid = false
  try { valid = crypto.verify(null, Buffer.from(canonical(d)), publicKey, Buffer.from(approval.signature, 'base64')) } catch {}
  if (!valid) return { ok: false, reason: 'signature invalid' }
  if (d.kind !== 'policy_approval') return { ok: false, reason: 'wrong kind of approval' }
  if (d.key_id !== K.fingerprint(publicKey)) return { ok: false, reason: 'approval was made with a different key' }
  if (d.policy_hash !== sha256(policy)) return { ok: false, reason: 'policy was changed after approval' }
  if (d.name !== policy.name) return { ok: false, reason: 'name in approval and policy does not match' }
  if (!(Date.parse(d.expires_at) > now.getTime())) return { ok: false, reason: `approval expired (${d.expires_at})` }
  const minimum = readState()[policy.name] || 0
  if (!(d.serial >= minimum)) return { ok: false, reason: `outdated approval (serial ${d.serial}, newest seen ${minimum})` }
  rememberSerial(policy.name, d.serial)
  return { ok: true, reason: '', policy, doc: d, policyDir: path.dirname(path.resolve(policyFile)) }
}

// Sign a policy (used by bin/sign-policy.js and by the tests).
function signPolicy (policyFile, privateKey, { days = 7, by = 'unknown', serial } = {}) {
  const policy = JSON.parse(fs.readFileSync(policyFile, 'utf8'))
  const now = new Date()
  const document = {
    kind: 'policy_approval',
    name: policy.name,
    policy_hash: sha256(policy),
    serial,
    approved_by: by,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + days * 86400000).toISOString(),
    key_id: K.fingerprint(crypto.createPublicKey(privateKey))
  }
  const signature = crypto.sign(null, Buffer.from(canonical(document)), privateKey).toString('base64')
  fs.writeFileSync(approvalFileFor(policyFile), JSON.stringify({ document, signature }, null, 2) + '\n')
  return document
}

module.exports = { verifyApproval, signPolicy, approvalFileFor }
