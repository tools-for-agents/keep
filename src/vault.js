// The vault: secret VALUES, encrypted at rest, and an index of their NAMES in the clear.
//
//   ~/.keep/secrets.enc   AES-256-GCM, one blob: { NAME: value }
//   ~/.keep/index.json    names, policy and usage — never a value
//   ~/.keep/audit.jsonl   every use: which names, which command, the exit code — never a value
//
// The 32-byte master key lives in the OS keychain when there is one (macOS `security`, Linux
// `secret-tool`), and in ~/.keep/master.key (0600) when there is not. The index records which,
// and `keep status` says it out loud: a file key is weaker, and nobody should have to guess.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const HOME = () => process.env.KEEP_HOME || path.join(os.homedir(), '.keep');
const P = (f) => path.join(HOME(), f);
const SERVICE = 'tools-for-agents.keep';
export const NAME_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;
export const MIN_LEN = 6;   // shorter than this and redaction would eat ordinary text

function ensureHome() { fs.mkdirSync(HOME(), { recursive: true, mode: 0o700 }); }
function readJson(f, d) { try { return JSON.parse(fs.readFileSync(P(f), 'utf8')); } catch { return d; } }
function writePrivate(f, text) {
  ensureHome();
  const tmp = P(`${f}.${process.pid}.tmp`);
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, P(f)); // atomic: a crash mid-write never leaves half a vault
}

// --- the master key -------------------------------------------------------------------------
function has(bin) { return spawnSync('/bin/sh', ['-c', `command -v ${bin}`], { encoding: 'utf8' }).status === 0; }
export function chooseBackend() {
  const forced = process.env.KEEP_BACKEND;
  if (forced) return forced;
  if (process.platform === 'darwin' && has('security')) return 'keychain';
  if (process.platform === 'linux' && has('secret-tool')) return 'secret-tool';
  return 'file';
}

const backends = {
  keychain: {
    // `security -i` reads its command from STDIN, so the key never appears in argv (and `ps`).
    put(hex) {
      const r = spawnSync('security', ['-i'], { input: `add-generic-password -U -a master -s ${SERVICE} -w ${hex}\n`, encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`keychain refused the key: ${(r.stderr || '').trim()}`);
    },
    get() {
      const r = spawnSync('security', ['find-generic-password', '-a', 'master', '-s', SERVICE, '-w'], { encoding: 'utf8' });
      return r.status === 0 ? r.stdout.trim() : null;
    },
    del() { spawnSync('security', ['delete-generic-password', '-a', 'master', '-s', SERVICE], { encoding: 'utf8' }); },
  },
  'secret-tool': {
    put(hex) {
      const r = spawnSync('secret-tool', ['store', '--label=keep master key', 'service', SERVICE, 'account', 'master'], { input: hex, encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`secret-tool refused the key: ${(r.stderr || '').trim()}`);
    },
    get() {
      const r = spawnSync('secret-tool', ['lookup', 'service', SERVICE, 'account', 'master'], { encoding: 'utf8' });
      return r.status === 0 && r.stdout.trim() ? r.stdout.trim() : null;
    },
    del() { spawnSync('secret-tool', ['clear', 'service', SERVICE, 'account', 'master']); },
  },
  file: {
    put(hex) { writePrivate('master.key', hex); },
    get() { try { return fs.readFileSync(P('master.key'), 'utf8').trim(); } catch { return null; } },
    del() { try { fs.unlinkSync(P('master.key')); } catch { /* gone */ } },
  },
};

export function index() {
  const i = readJson('index.json', null);
  return i && typeof i === 'object' ? { secrets: {}, requests: [], ...i } : null;
}
function saveIndex(i) { writePrivate('index.json', `${JSON.stringify(i, null, 2)}\n`); }

export function init() {
  const existing = index();
  if (existing) return { backend: existing.backend, created: false };
  const backend = chooseBackend();
  const b = backends[backend];
  if (!b) throw new Error(`unknown KEEP_BACKEND "${backend}" (keychain | secret-tool | file)`);
  if (!b.get()) b.put(crypto.randomBytes(32).toString('hex'));
  saveIndex({ backend, created: new Date().toISOString(), secrets: {}, requests: [] });
  writeValues({}, backend);
  return { backend, created: true };
}

function key(backend) {
  const hex = backends[backend]?.get();
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) throw new Error(`the master key is missing from the ${backend} backend — the vault cannot be opened`);
  return Buffer.from(hex, 'hex');
}

function readValues(backend) {
  const blob = readJson('secrets.enc', null);
  if (!blob) return {};
  const d = crypto.createDecipheriv('aes-256-gcm', key(backend), Buffer.from(blob.iv, 'base64'));
  d.setAuthTag(Buffer.from(blob.tag, 'base64'));
  try {
    return JSON.parse(Buffer.concat([d.update(Buffer.from(blob.data, 'base64')), d.final()]).toString('utf8'));
  } catch { throw new Error('the vault did not decrypt — it was altered, or the master key changed'); }
}
function writeValues(values, backend) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(backend), iv);
  const data = Buffer.concat([c.update(JSON.stringify(values), 'utf8'), c.final()]);
  writePrivate('secrets.enc', `${JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') })}\n`);
}

function open() {
  const i = index();
  if (!i) throw new Error('no vault yet — run: keep init');
  return i;
}

export function checkName(name) {
  if (!NAME_RE.test(String(name))) throw new Error(`"${name}" is not a secret name — use UPPER_SNAKE_CASE, like an env var (it becomes one)`);
}

export function set(name, value, { allow = ['*'], note = '' } = {}) {
  checkName(name);
  const v = String(value).replace(/\r?\n$/, '');
  if (!v) throw new Error('empty value — nothing to keep');
  if (v.length < MIN_LEN) throw new Error(`a ${v.length}-character value cannot be redacted safely (it would erase ordinary text); keep only real secrets, ${MIN_LEN}+ characters`);
  const i = open();
  const values = readValues(i.backend);
  const existed = name in values;
  values[name] = v;
  writeValues(values, i.backend);
  const prev = i.secrets[name] || {};
  i.secrets[name] = { allow: normAllow(allow), note, created: prev.created || new Date().toISOString(), updated: new Date().toISOString(), uses: prev.uses || 0, lastUsed: prev.lastUsed || null, length: v.length };
  i.requests = i.requests.filter((r) => r.name !== name); // a request is answered by the secret arriving
  saveIndex(i);
  return { name, replaced: existed };
}

export function normAllow(a) {
  const list = (Array.isArray(a) ? a : String(a || '*').split(',')).map((s) => s.trim()).filter(Boolean);
  return list.length ? list : ['*'];
}

export function remove(name) {
  const i = open();
  const values = readValues(i.backend);
  if (!(name in values) && !i.secrets[name]) return false;
  delete values[name];
  delete i.secrets[name];
  writeValues(values, i.backend);
  saveIndex(i);
  return true;
}

// Names and policy only. There is deliberately no function here that returns one value by name
// to a caller outside this package's run/scan paths.
export function list() {
  const i = index();
  if (!i) return [];
  return Object.entries(i.secrets).map(([name, m]) => ({ name, ...m })).sort((a, b) => a.name.localeCompare(b.name));
}

// Internal: run.js and scan.js need values to inject and to redact. Not exported by the CLI/MCP.
export function _values(names) {
  const i = open();
  const all = readValues(i.backend);
  if (!names) return all;
  const out = {};
  for (const n of names) {
    if (!(n in all)) throw new Error(`no secret named ${n} — \`keep list\` shows what exists; ask your person to \`keep set ${n}\``);
    out[n] = all[n];
  }
  return out;
}

export function recordUse(names) {
  const i = index();
  if (!i) return;
  const now = new Date().toISOString();
  for (const n of names) if (i.secrets[n]) { i.secrets[n].uses = (i.secrets[n].uses || 0) + 1; i.secrets[n].lastUsed = now; }
  saveIndex(i);
}

export function audit(entry) {
  ensureHome();
  fs.appendFileSync(P('audit.jsonl'), `${JSON.stringify({ when: new Date().toISOString(), ...entry })}\n`, { mode: 0o600 });
}
export function auditLog(limit = 50) {
  try {
    return fs.readFileSync(P('audit.jsonl'), 'utf8').trim().split('\n').filter(Boolean).slice(-limit).map((l) => JSON.parse(l));
  } catch { return []; }
}

// An agent that needs a secret it does not have asks for it. The request is what the person
// sees in `keep list`; it is answered the moment they `keep set` that name.
export function request(name, why = '') {
  checkName(name);
  const i = open();
  if (i.secrets[name]) return { exists: true, name };
  i.requests = [...i.requests.filter((r) => r.name !== name), { name, why: String(why).slice(0, 300), when: new Date().toISOString() }];
  saveIndex(i);
  return { requested: true, name };
}

export function status() {
  const i = index();
  if (!i) return { initialised: false, home: HOME() };
  let opens = true;
  try { readValues(i.backend); } catch { opens = false; }
  return { initialised: true, home: HOME(), backend: i.backend, secrets: Object.keys(i.secrets).length, requests: i.requests, opens, weak: i.backend === 'file' };
}

export function destroy() {
  const i = index();
  if (i) backends[i.backend]?.del();
  for (const f of ['secrets.enc', 'index.json', 'master.key']) { try { fs.unlinkSync(P(f)); } catch { /* gone */ } }
}
