#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// verify-audit.js: check whether audit files were changed afterwards.
// Inside a file the hash chain shows changed, removed or inserted lines. The end of a file is checked
// against the anchor the gateway keeps in ~/.sealgate/audit_heads: cut-off lines, added lines and a log
// rewritten as a whole are detected. Logs without an anchor (written before 0.4.0, or on another machine)
// are checked by their chain only, and the output says so.
//
//   node bin/verify-audit.js <file.jsonl> [...]    check these files
//   node bin/verify-audit.js --all                 check every log this machine has an anchor for,
//                                                  including logs that were deleted
const fs = require('fs')
const path = require('path')
const K = require('../src/keys')
const { verifyChain, readHead, listHeads, runOf } = require('../src/audit')

const args = process.argv.slice(2)
if (!args.length) { console.log('usage: node bin/verify-audit.js <file.jsonl> [...]   or   node bin/verify-audit.js --all'); process.exit(1) }
let allOk = true
const show = (ok, name, text) => { if (!ok) allOk = false; console.log(`${ok ? 'intact  ' : 'CHANGED '}  ${name}  ${text}`) }

if (args.includes('--all')) {
  const heads = listHeads(K.AUDIT_HEADS)
  if (!heads.length) console.log(`No anchors in ${K.AUDIT_HEADS}.`)
  for (const h of heads) {
    if (!fs.existsSync(h.file)) { show(false, path.basename(h.file), `the gateway wrote ${h.n} lines to ${h.file}, but the file is gone`); continue }
    const r = verifyChain(h.file, h)
    show(r.ok, path.basename(h.file), `(${r.lines} lines, end anchored)${r.error ? '  ' + r.error : ''}`)
  }
} else {
  for (const f of args) {
    const run = runOf(f)
    const head = run ? readHead(K.AUDIT_HEADS, run) : null
    const r = verifyChain(f, head)
    show(r.ok, path.basename(f), `(${r.lines} lines, ${r.anchored || head ? 'end anchored' : 'no anchor on this machine: the end of the log is not checked'})${r.error ? '  ' + r.error : ''}`)
  }
}
process.exit(allOk ? 0 : 2)
