// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// audit.js: every decision as one JSON line, chained by hashes.
// Each line contains the hash of the previous one. If a line in the middle is later changed,
// removed or inserted, the chain breaks and bin/verify-audit.js shows where.
//
// The chain alone cannot show that lines at the END were cut off, and it cannot show a log that was
// rewritten as a whole with new hashes. For that the gateway keeps an anchor outside the log: after every
// line it records the line number and hash of the last line in ~/.sealgate/audit_heads (the directory that
// no agent tool can reach). A log is intact only if it ends exactly where its anchor says.

const fs = require('fs')
const path = require('path')
const { sha256 } = require('./gates')

const GENESIS = '0'.repeat(64)

class AuditLog {
  constructor (dir, run, { headDir } = {}) {
    fs.mkdirSync(dir, { recursive: true })
    // Every gateway gets its own file. If the name is taken (two gateways started in the same millisecond),
    // a number is added: two writers in one file would break the hash chain.
    let name = run
    for (let i = 2; ; i++) {
      try { fs.closeSync(fs.openSync(path.join(dir, `${name}.jsonl`), 'wx')); break } catch (e) { if (e.code !== 'EEXIST') throw e; name = `${run}-${i}` }
    }
    this.file = path.join(dir, `${name}.jsonl`)
    this.run = name
    this.headFile = null
    if (headDir) { fs.mkdirSync(headDir, { recursive: true, mode: 0o700 }); this.headFile = path.join(headDir, `${name}.json`) }
    this.prev = GENESIS
    this.n = 0
  }

  write (entry) {
    const line = { n: ++this.n, time: new Date().toISOString(), run: this.run, ...entry, prev: this.prev }
    line.hash = sha256(line)
    this.prev = line.hash
    fs.appendFileSync(this.file, JSON.stringify(line) + '\n')
    if (this.headFile) {
      const tmp = `${this.headFile}.tmp`
      fs.writeFileSync(tmp, JSON.stringify({ run: this.run, file: path.resolve(this.file), n: line.n, hash: line.hash, time: line.time }), { mode: 0o600 })
      fs.renameSync(tmp, this.headFile)
    }
    return line
  }
}

// The anchor the gateway recorded for a run, or null. { run, file, n, hash, time }
function readHead (headDir, run) {
  try { const h = JSON.parse(fs.readFileSync(path.join(headDir, `${run}.json`), 'utf8')); return h && typeof h.n === 'number' && typeof h.hash === 'string' ? h : null } catch { return null }
}
// All anchors in a directory.
function listHeads (headDir) {
  let names = []
  try { names = fs.readdirSync(headDir).filter(f => f.endsWith('.json')).sort() } catch {}
  return names.map(f => readHead(headDir, f.slice(0, -5))).filter(Boolean)
}
// The run name written into the first line of a log (survives renaming the file), or null.
function runOf (file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8').split('\n').find(Boolean)).run || null } catch { return null }
}

// Verify an audit file. Returns { ok, lines, error, anchored }.
// With head (the anchor from readHead) the end of the log is checked too: cut-off lines, added lines and
// a log rewritten as a whole are detected. Without head only the chain inside the file is checked.
function verifyChain (file, head) {
  const r = verifyLines(file)
  if (!r.ok || !head) return { ok: r.ok, lines: r.lines, error: r.error, anchored: false }
  if (r.lines < head.n) return { ok: false, lines: r.lines, error: `log ends at line ${r.lines}, but the gateway wrote ${head.n}: lines at the end are missing`, anchored: true }
  if (r.lines > head.n) return { ok: false, lines: r.lines, error: `log has ${r.lines} lines, but the gateway recorded only ${head.n}: lines were added, or the gateway stopped before recording the last one`, anchored: true }
  if (r.last !== head.hash) return { ok: false, lines: r.lines, error: 'the last line is not the one the gateway recorded: the log was rewritten', anchored: true }
  return { ok: true, lines: r.lines, error: '', anchored: true }
}

function verifyLines (file) {
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
  return { ok: true, lines: lines.length, error: '', last: prev }
}

module.exports = { AuditLog, verifyChain, readHead, listHeads, runOf }
