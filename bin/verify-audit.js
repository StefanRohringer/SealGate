#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// verify-audit.js: check whether audit files were changed afterwards (hash chain).
// Usage: node bin/verify-audit.js <file.jsonl> [...]
const path = require('path')
const { verifyChain } = require('../src/audit')
const files = process.argv.slice(2)
if (!files.length) { console.log('usage: node bin/verify-audit.js <file.jsonl> [...]'); process.exit(1) }
let allOk = true
for (const f of files) {
  const r = verifyChain(f)
  if (!r.ok) allOk = false
  console.log(`${r.ok ? 'intact  ' : 'CHANGED '}  ${path.basename(f)}  (${r.lines} lines)${r.error ? '  ' + r.error : ''}`)
}
process.exit(allOk ? 0 : 2)
