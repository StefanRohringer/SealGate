// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// api-key.js: find an Anthropic API key that actually works.
// Tries in order: --key-file <path>, ANTHROPIC_API_KEY, <sealgate dir>/api_key (default ~/.sealgate/api_key).
// Each candidate is checked with a free request (list of models). The key is never printed.

const fs = require('fs')
const os = require('os')
const path = require('path')

async function findApiKey (keyFile, sealgateDir) {
  const dir = sealgateDir || process.env.SEALGATE_DIR || path.join(os.homedir(), '.sealgate')
  const candidates = []
  if (keyFile) candidates.push([keyFile, () => fs.readFileSync(keyFile, 'utf8')])
  candidates.push(['ANTHROPIC_API_KEY', () => process.env.ANTHROPIC_API_KEY || ''])
  const keyPath = path.join(dir, 'api_key')
  candidates.push([keyPath.replace(os.homedir(), '~'), () => fs.readFileSync(keyPath, 'utf8')])
  const seen = new Set()
  for (const [name, read] of candidates) {
    let k = ''
    try { k = read().trim() } catch { if (name !== 'ANTHROPIC_API_KEY') console.log(`Not found: ${name}`); continue }
    if (!k || seen.has(k)) continue
    seen.add(k)
    if (!/^sk-ant-[A-Za-z0-9_-]{20,}$/.test(k)) { console.log(`Skipped: ${name} does not look like an API key.`); continue }
    let status = 0
    try {
      const res = await fetch('https://api.anthropic.com/v1/models?limit=1', { headers: { 'x-api-key': k, 'anthropic-version': '2023-06-01' } })
      status = res.status
    } catch (e) { console.log(`Cannot reach the API: ${e.message}`); process.exit(1) }
    if (status === 200) { console.log(`Using API key from ${name}.`); return k }
    console.log(`Skipped: ${name} was rejected by the API (${status}).`)
  }
  console.log('No working API key found (--key-file, ANTHROPIC_API_KEY or ~/.sealgate/api_key).')
  process.exit(1)
}

module.exports = { findApiKey }
