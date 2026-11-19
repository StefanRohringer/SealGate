// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// gates.js: pure checking logic. Knows nothing about MCP or any specific tool.
// Every check returns { ok, gate, reason }. Principle: when in doubt, deny (fail closed).

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

// Canonical JSON: object keys sorted, so the same content always hashes the same.
function canonical (value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  }
  return JSON.stringify(value === undefined ? null : value)
}
const sha256 = (value) => crypto.createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex')

const allow = (gate) => ({ ok: true, gate, reason: '' })
const deny = (gate, reason) => ({ ok: false, gate, reason })

// Read a field from the input, nested fields with dots ("address.city").
function getField (input, field) {
  let v = input
  for (const part of String(field).split('.')) {
    if (v == null || typeof v !== 'object' || !Object.prototype.hasOwnProperty.call(v, part)) return { present: false }
    v = v[part]
  }
  return { present: true, value: v }
}

// Real path: resolve symlinks in the existing part, so a link cannot lead out of a folder.
function realPath (p) {
  let abs = path.resolve(p)
  const rest = []
  while (!fs.existsSync(abs)) {
    const up = path.dirname(abs)
    if (up === abs) break
    rest.unshift(path.basename(abs))
    abs = up
  }
  return path.join(fs.realpathSync(abs), ...rest)
}
function isInside (p, folder) {
  const rel = path.relative(folder, p)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}
const short = (v) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > 80 ? s.slice(0, 80) + '...' : s }

// Check types. c = the check from the policy, v = the value from the input,
// ctx = { policyDir, targetDir, protected } for paths. Each returns an error text or null.
const CHECKS = {
  allow_list (v, c) {
    return c.values.some(x => x === v) ? null : `"${short(v)}" is not on the allow list`
  },
  deny_list (v, c) {
    return c.values.some(x => x === v) ? `"${short(v)}" is explicitly denied` : null
  },
  pattern (v, c) {
    if (typeof v !== 'string') return 'text expected'
    return new RegExp(c.pattern).test(v) ? null : `"${short(v)}" does not match the allowed pattern`
  },
  deny_pattern (v, c) {
    const text = typeof v === 'string' ? v : JSON.stringify(v)
    const hit = [].concat(c.patterns).find(m => new RegExp(m, 'i').test(text))
    return hit ? `contains forbidden content (pattern ${hit})` : null
  },
  number (v, c) {
    if (typeof v !== 'number' || !Number.isFinite(v)) return 'number expected'
    if (c.integer && !Number.isInteger(v)) return 'integer expected'
    if (c.min != null && v < c.min) return `${v} is below ${c.min}`
    if (c.max != null && v > c.max) return `${v} is above ${c.max}`
    return null
  },
  max_length (v, c) {
    const n = typeof v === 'string' || Array.isArray(v) ? v.length : JSON.stringify(v).length
    return n > c.max ? `too long (${n}, at most ${c.max})` : null
  },
  type (v, c) {
    const t = Array.isArray(v) ? 'array' : (v === null ? 'null' : typeof v)
    return t === c.is ? null : `type ${t} instead of ${c.is}`
  },
  path_within (v, c, ctx) {
    if (typeof v !== 'string' || v.includes('\0')) return 'path expected'
    if (v.trim() === '') v = '.' // an empty path means the working folder itself
    let target
    try { target = realPath(path.resolve(ctx.targetDir, v)) } catch (e) { return `path cannot be checked: ${e.message}` }
    // The SealGate directory (keys, emergency stop, approvals) is never reachable, whatever the policy says.
    for (const g of ctx.protected || []) { try { if (isInside(target, realPath(g))) return 'path points into the protected SealGate directory' } catch {} }
    const allowed = [].concat(c.folders).map(o => { try { return realPath(path.resolve(ctx.policyDir, o)) } catch { return null } }).filter(Boolean)
    return allowed.some(o => isInside(target, o)) ? null : `path is outside the allowed folders (${v})`
  },
  box (v, c) {
    if (!Array.isArray(v) || v.length !== c.min.length || !v.every(Number.isFinite)) return `point with ${c.min.length} numbers expected`
    for (let i = 0; i < v.length; i++) if (v.at(i) < c.min.at(i) || v.at(i) > c.max.at(i)) return `point ${JSON.stringify(v)} is outside ${JSON.stringify(c.min)} to ${JSON.stringify(c.max)}`
    return null
  }
}

// Check an input against the rule of one tool.
function checkInput (rule, input, ctx) {
  if (input == null) input = {}
  if (typeof input !== 'object' || Array.isArray(input)) return deny('input', 'input must be an object')
  const checks = rule.checks || []

  // Only known fields: anything not named in a check or in "extra_fields" is denied.
  const known = new Set([...checks.map(c => String(c.field).split('.')[0]), ...(rule.extra_fields || [])])
  const unknown = Object.keys(input).filter(f => !known.has(f))
  if (unknown.length) return deny('fields', `unknown fields: ${unknown.join(', ')}`)

  for (const c of checks) {
    const fn = CHECKS[c.type]
    if (!fn) return deny('policy', `unknown check type "${c.type}" in the policy`)
    const f = getField(input, c.field)
    if (!f.present) {
      if (c.optional) continue
      return deny(c.field, `field "${c.field}" is missing`)
    }
    let error
    try { error = fn(f.value, c, ctx) } catch (e) { error = `check failed: ${e.message}` }
    if (error) return deny(c.field, error)
  }
  return allow('input')
}

// Does this call need a human? "sofar" = what already passed without a human in the rolling window.
// With rolling_sum_seconds a large order cannot be split into many small ones below the threshold.
function needsHuman (rule, input, sofar = 0) {
  const a = rule.human_approval
  if (!a) return false
  if (a === true) return true
  const f = getField(input || {}, a.field)
  if (!f.present) return true
  if (a.at_least != null) return typeof f.value !== 'number' || f.value + (a.rolling_sum_seconds ? sofar : 0) >= a.at_least
  if (a.values) return a.values.includes(f.value)
  return true
}

// Rate limits and rolling sums over a sliding window (in memory).
class Counter {
  constructor () { this.times = new Map(); this.values = new Map() }
  check (key, limit, now = Date.now()) {
    if (!limit) return allow('rate')
    const window = limit.per_seconds * 1000
    const list = (this.times.get(key) || []).filter(t => now - t < window)
    this.times.set(key, list)
    if (list.length >= limit.count) return deny('rate', `at most ${limit.count} calls in ${limit.per_seconds} seconds`)
    return allow('rate')
  }
  record (key, now = Date.now()) {
    const list = this.times.get(key) || []
    list.push(now)
    this.times.set(key, list)
  }
  sum (key, perSeconds, now = Date.now()) {
    const list = (this.values.get(key) || []).filter(([t]) => now - t < perSeconds * 1000)
    this.values.set(key, list)
    return list.reduce((s, [, v]) => s + v, 0)
  }
  add (key, value, now = Date.now()) {
    const list = this.values.get(key) || []
    list.push([now, value])
    this.values.set(key, list)
  }
}

// Redact secrets in responses before the model sees them.
function redact (text, patterns) {
  let n = 0
  for (const p of patterns || []) text = text.replace(new RegExp(p, 'g'), () => { n++; return '[REDACTED]' })
  return { text, count: n }
}

module.exports = { canonical, sha256, getField, realPath, checkInput, needsHuman, Counter, redact, CHECKS }
