// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// server.js: a deliberately NAIVE MCP server for the demo, the way many quick integrations are built.
// It checks nothing: reads and writes any file, emails anyone, orders any amount.
// Without a gateway a model could do anything with it. With SealGate in front, acme.policy.json applies.
// Emails and orders are not really sent, they are logged in data/.
// run_command executes nothing in this demo, it only stands for a dangerous tool.
const fs = require('fs')
const path = require('path')
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js')
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js')
const { z } = require('zod')

const ROOT = process.cwd()
const text = (t) => ({ content: [{ type: 'text', text: typeof t === 'string' ? t : JSON.stringify(t, null, 1) }] })
const server = new McpServer({ name: 'acme', version: '0.1.0' })

server.registerTool('read_file', { description: 'Reads a text file.', inputSchema: { path: z.string() } },
  async ({ path: p }) => text(fs.readFileSync(path.resolve(ROOT, p), 'utf8')))

server.registerTool('list_folder', { description: 'Lists the files in a folder.', inputSchema: { path: z.string() } },
  async ({ path: p }) => text(fs.readdirSync(path.resolve(ROOT, p), { withFileTypes: true }).map(e => (e.isDirectory() ? '[folder] ' : '') + e.name)))

server.registerTool('write_file', { description: 'Writes a text file.', inputSchema: { path: z.string(), content: z.string() } },
  async ({ path: p, content }) => { const f = path.resolve(ROOT, p); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, content); return text({ result: 'written', path: p }) })

server.registerTool('send_email', { description: 'Sends an email.', inputSchema: { to: z.string(), subject: z.string(), body: z.string() } },
  async (m) => { fs.appendFileSync(path.join(ROOT, 'sent_mail.jsonl'), JSON.stringify({ time: new Date().toISOString(), ...m }) + '\n'); return text({ result: 'sent', to: m.to }) })

server.registerTool('place_order', { description: 'Orders material from the supplier.', inputSchema: { item: z.string(), quantity_kg: z.number(), price_eur: z.number() } },
  async (o) => { fs.appendFileSync(path.join(ROOT, 'orders.jsonl'), JSON.stringify({ time: new Date().toISOString(), ...o }) + '\n'); return text({ result: 'ordered', ...o }) })

server.registerTool('run_command', { description: 'Runs a shell command.', inputSchema: { command: z.string() } },
  async ({ command }) => text({ result: 'demo: not executed', command }))

server.connect(new StdioServerTransport())
