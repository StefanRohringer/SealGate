// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// audit.js: every decision as one JSON line, chained by hashes.
// Each line contains the hash of the previous one. If a line in the middle is later changed,
// removed or inserted, the chain breaks and bin/verify-audit.js shows where.

const fs = require('fs')
const path = require('path')
const { sha256 } = require('./gates')

const GENESIS = '0'.repeat(64)

class AuditLog {
  constructor (dir, run) {
    fs.mkdirSync(dir, { recursive: true })
    // Every gateway gets its own file. If the name is taken (two gateways started in the same millisecond),
    // a number is added: two writers in one file would break the hash chain.
    let name = run
    for (let i = 2; ; i++) {
      try { fs.closeSync(fs.openSync(path.join(dir, `${name}.jsonl`), 'wx')); break } catch (e) { if (e.code !== 'EEXIST') throw e; name = `${run}-${i}` }
    }
    this.file = path.join(dir, `${name}.jsonl`)
    this.run = name
    this.prev = GENESIS
    this.n = 0
  }

  write (entry) {
    const line = { n: ++this.n, time: new Date().toISOString(), run: this.run, ...entry, prev: this.prev }
    line.hash = sha256(line)
    this.prev = line.hash
    fs.appendFileSync(this.file, JSON.stringify(line) + '\n')
    return line
  }
}

// Verify an audit file. Returns { ok, lines, error }.
function verifyChain (file) {
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
  let prev = GENESIS
  for (let i = 0; i < lines.length; i++) {
    let l
    try { l = JSON.parse(lines.at(i)) } catch { return { ok: false, lines: lines.length, error: `line ${i + 1} is not JSON` } }
    const { hash: stored, ...rest } = l
    if (l.prev !== prev) return { ok: false, lines: lines.length, error: `line ${i + 1}: chain broken (a line before it is missing or changed)` }
    if (sha256(rest) !== stored) return { ok: false, lines: lines.length, error: `line ${i + 1}: content was changed` }
    if (l.n !== i + 1) return { ok: false, lines: lines.length, error: `line ${i + 1}: wrong number (${l.n})` }
    prev = stored
  }
  return { ok: true, lines: lines.length, error: '' }
}

module.exports = { AuditLog, verifyChain }
