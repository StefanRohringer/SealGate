#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Rohringer
'use strict'
// estop.js: emergency stop for all SealGate gateways on this machine.
//   node bin/estop.js on   -> every call is denied immediately
//   node bin/estop.js off  -> normal operation
const fs = require('fs')
const K = require('../src/keys')
const what = process.argv[2]
if (what === 'on') { fs.mkdirSync(K.DIR, { recursive: true, mode: 0o700 }); fs.writeFileSync(K.ESTOP, new Date().toISOString() + '\n'); console.log('Emergency stop ON. All calls are denied.') }
else if (what === 'off') { try { fs.unlinkSync(K.ESTOP) } catch {} console.log('Emergency stop off.') }
else console.log(`Emergency stop is ${fs.existsSync(K.ESTOP) ? 'ON' : 'off'}. Usage: node bin/estop.js on | off`)
