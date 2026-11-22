// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// audit.test.js: the audit log must show every kind of tampering, also at its end.
// The hash chain covers the inside of a file. The anchor outside the log covers the end. Needs no MCP packages.
// Run: node test/audit.test.js

const fs = require('fs')
const os = require('os')
const path = require('path')
const { AuditLog, verifyChain, readHead, listHeads, runOf } = require('../src/audit')
const { sha256 } = require('../src/gates')

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sealgate-audit-'))
const LOGS = path.join(TMP, 'audit'); const HEADS = path.join(TMP, 'sealgate', 'audit_heads')

let passed = 0; let total = 0
function expect (title, actual, wanted) {
  total++
  const ok = actual === wanted
  if (ok) passed++
  console.log(`${ok ? '\x1b[32m ok \x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${title.padEnd(58)} ${actual}${ok ? '' : `  (expected ${wanted})`}`)
}
const verdict = (file, head) => { const r = verifyChain(file, head); return r.ok ? 'intact' : r.error.split(':')[0].replace(/\d+/g, 'N') }

const log = new AuditLog(LOGS, 'acme_run', { headDir: HEADS })
log.write({ event: 'start' })
for (let i = 1; i <= 6; i++) log.write({ tool: 'place_order', input: { price_eur: 100 * i }, verdict: i === 4 ? 'denied' : 'executed' })
const head = readHead(HEADS, runOf(log.file))
const lines = fs.readFileSync(log.file, 'utf8').split('\n').filter(Boolean)
const variant = (name, list) => { const f = path.join(TMP, name + '.jsonl'); fs.writeFileSync(f, list.join('\n') + '\n'); return f }
// Somebody who rewrites the log can also recompute the chain, because the chain uses no secret.
const rechain = (entries) => { let prev = '0'.repeat(64); return entries.map((e, i) => { const { hash, ...rest } = e; const l = { ...rest, n: i + 1, prev }; l.hash = sha256(l); prev = l.hash; return JSON.stringify(l) }) }
const parsed = lines.map(l => JSON.parse(l))

console.log('\nUntouched log')
expect('anchor exists and names the last line', String(head && head.n === 7 && head.hash === parsed.at(-1).hash), 'true')
expect('intact with anchor', verdict(log.file, head), 'intact')
expect('intact without anchor (chain only)', verdict(log.file), 'intact')

console.log('\nTampering that the chain alone already shows')
const changed = parsed.map(e => ({ ...e })); changed[3].input = { price_eur: 1 }
expect('one line changed', verdict(variant('changed', changed.map(e => JSON.stringify(e))), head), 'line N')
expect('one line removed in the middle', verdict(variant('removed', lines.filter((_, i) => i !== 3)), head), 'line N')

console.log('\nTampering that only the anchor shows')
const cut = variant('cut', lines.slice(0, 4))
expect('last three lines cut off, without anchor: not noticed', verdict(cut), 'intact')
expect('last three lines cut off, with anchor', verdict(cut, head), 'log ends at line N, but the gateway wrote N')
const rewritten = variant('rewritten', rechain(parsed.filter(e => e.verdict !== 'denied').concat([{ time: 't', run: 'acme_run', tool: 'place_order', verdict: 'executed' }])))
expect('whole log rewritten with a new chain, without anchor: not noticed', verdict(rewritten), 'intact')
expect('whole log rewritten with a new chain, with anchor', verdict(rewritten, head), 'the last line is not the one the gateway recorded')
const added = variant('added', rechain(parsed.concat([{ time: 't', run: 'acme_run', tool: 'send_email', verdict: 'executed' }])))
expect('a line added at the end', verdict(added, head), 'log has N lines, but the gateway recorded only N')
expect('log emptied', verdict(variant('empty', []), head), 'log ends at line N, but the gateway wrote N')

console.log('\nFinding logs')
expect('the run name is read from the log, not from the file name', runOf(cut), 'acme_run')
const second = new AuditLog(LOGS, 'acme_run', { headDir: HEADS }); second.write({ event: 'start' })
expect('a second gateway gets its own anchor', String(listHeads(HEADS).length), '2')
fs.rmSync(second.file)
expect('a deleted log is still listed by its anchor', String(listHeads(HEADS).filter(h => !fs.existsSync(h.file)).length), '1')
expect('anchor file is private (mode 600)', (fs.statSync(path.join(HEADS, 'acme_run.json')).mode & 0o777).toString(8), '600')

console.log(`\n${passed} of ${total} checks passed.`)
fs.rmSync(TMP, { recursive: true, force: true })
process.exit(passed === total ? 0 : 1)
