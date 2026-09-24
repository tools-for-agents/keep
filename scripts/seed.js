#!/usr/bin/env node
// A vault with something in it, for the kit's gates: two secrets, one restricted, and one request.
// Refuses to touch the real vault or the real keychain — a gate must never seed the machine it runs on.
import * as vault from '../src/vault.js';

if (!process.env.KEEP_HOME) { console.error('seed: set KEEP_HOME — refusing to seed ~/.keep'); process.exit(1); }
if (process.env.KEEP_BACKEND !== 'file') { console.error('seed: set KEEP_BACKEND=file — refusing to write a key into the keychain'); process.exit(1); }
vault.init();
vault.set('SEED_API_KEY', 'seed-value-not-a-real-key-0001');
vault.set('SEED_GH_TOKEN', 'seed-value-not-a-real-key-0002', { allow: 'gh' });
vault.request('SEED_WANTED', 'a request the person has not answered yet');
console.log(`seeded ${vault.HOME()}: ${vault.list().length} secrets, ${vault.status().requests.length} request`);
