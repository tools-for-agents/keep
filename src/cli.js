#!/usr/bin/env node
// keep — use a secret without holding it. See README.md.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as vault from './vault.js';
import { run } from './run.js';
import { scan, summarise, transcriptsDir, redactPatterns } from './scan.js';
import { needles, redactText } from './redact.js';
import { judge } from './guard.js';
import os from 'node:os';

const argv = process.argv.slice(2);
const dash = argv.indexOf('--');
const head = dash < 0 ? argv : argv.slice(0, dash);
const tail = dash < 0 ? [] : argv.slice(dash + 1);
const [cmd = 'help', ...rest] = head;
const { args, flags } = parse(rest);
const out = (s) => process.stdout.write(`${s}\n`);
const die = (s, code = 1) => { process.stderr.write(`keep: ${s}\n`); process.exit(code); };
const ago = (iso) => { if (!iso) return 'never'; const m = Math.round((Date.now() - new Date(iso)) / 60000); return m < 60 ? `${m}m ago` : m < 2880 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`; };

const commands = {
  init() {
    const r = vault.init();
    out(r.created ? `vault created at ${vault.HOME()} — master key in: ${r.backend}` : `vault already exists at ${vault.HOME()} (${r.backend})`);
    if (r.backend === 'file') out('note: no OS keychain found, so the master key is a 0600 file beside the vault. Anyone who can read your home directory can read both.');
  },
  async set() {
    const name = args[0];
    if (!name) die('usage: keep set NAME [--allow cmd1,cmd2] [--note "…"]   (the value is read from stdin, or typed hidden)');
    vault.checkName(name);
    vault.init();
    const value = await readSecret(`value for ${name} (hidden): `);
    const r = vault.set(name, value, { allow: flags.allow || '*', note: flags.note || '' });
    out(`${r.replaced ? 'replaced' : 'kept'} ${name}${flags.allow ? ` — only for: ${vault.normAllow(flags.allow).join(', ')}` : ''}`);
  },
  import() {
    const file = args[0];
    if (!file) die('usage: keep import path/to/.env [--allow cmd1,cmd2]');
    vault.init();
    const kept = [];
    const skipped = [];
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
      if (!m) continue;
      const name = m[1].toUpperCase();
      const value = m[2].replace(/^(['"])(.*)\1$/, '$2');
      try { vault.set(name, value, { allow: flags.allow || '*', note: `imported from ${path.basename(file)}` }); kept.push(name); } catch (e) { skipped.push(`${name} (${e.message.split(' — ')[0]})`); }
    }
    out(`kept ${kept.length}: ${kept.join(', ') || '—'}`);
    if (skipped.length) out(`skipped ${skipped.length}: ${skipped.join('; ')}`);
    if (kept.length) out(`The values are still in ${file}. Delete it, or they are kept twice — once safely.`);
  },
  list() {
    const s = vault.status();
    if (!s.initialised) return out('no vault yet — keep init');
    const rows = vault.list();
    if (!rows.length) out('(no secrets kept)');
    for (const r of rows) out(`${r.name.padEnd(28)} ${String(r.length).padStart(4)} chars   used ${String(r.uses).padStart(3)}×, last ${ago(r.lastUsed).padEnd(9)}  ${r.allow.includes('*') ? 'any command' : `only: ${r.allow.join(', ')}`}${r.note ? `   · ${r.note}` : ''}`);
    if (s.requests.length) {
      out('\nasked for, not yet kept:');
      for (const q of s.requests) out(`  ${q.name.padEnd(26)} ${ago(q.when)}${q.why ? ` — ${q.why}` : ''}   → keep set ${q.name}`);
    }
  },
  rm() { const n = args[0]; if (!n) die('usage: keep rm NAME'); out(vault.remove(n) ? `forgot ${n}` : `no secret named ${n}`); },
  async run() {
    if (!tail.length) die('usage: keep run [--with NAME,NAME] [--timeout seconds] -- command args…   ({{NAME}} in an argument is replaced too)');
    const r = await run({
      argv: tail,
      with: flags.with ? String(flags.with).split(',').map((s) => s.trim()).filter(Boolean) : [],
      mode: 'stream',
      stdin: 'inherit',
      timeoutMs: (Number(flags.timeout) || 3600) * 1000,
    });
    if (r.error) die(r.error, 127);
    if (r.redactions) process.stderr.write(`keep: ${r.redactions} secret value${r.redactions === 1 ? '' : 's'} redacted from the output\n`);
    if (r.signal === 'timeout') die(`timed out`, 124);
    process.exitCode = r.exit ?? 1;
  },
  scan() {
    const roots = [...args];
    if (flags.transcripts) roots.push(transcriptsDir());
    if (!roots.length) roots.push(process.cwd());
    let values = {};
    try { values = vault.status().initialised ? vault._values() : {}; } catch (e) { process.stderr.write(`keep: cannot open the vault (${e.message}); scanning for patterns only\n`); }
    const r = scan(roots, values, { patterns: !flags['no-patterns'] });
    const groups = summarise(r.findings);
    if (flags.json) return out(JSON.stringify({ ...r, findings: groups }, null, 2));
    out(`scanned ${r.files} files (${(r.bytes / 1048576).toFixed(1)} MB) in ${roots.join(', ')}`);
    if (!groups.length) return out('nothing found — no kept value and no known key shape.');
    for (const g of groups) {
      const where = `${g.file}:${g.lines.slice(0, 5).join(',')}${g.lines.length > 5 ? ` (+${g.lines.length - 5} more)` : ''}`;
      out(g.kind === 'kept' ? `LEAK   ${g.name.padEnd(24)} ${where}` : `maybe  ${`${g.name} ${g.preview}`.padEnd(24)} ${where}`);
    }
    const leaks = groups.filter((g) => g.kind === 'kept').length;
    if (leaks) out(`\n${leaks} file${leaks === 1 ? '' : 's'} hold a kept secret. Rotate the secret — a leaked value stays leaked — then keep set the new one.`);
    if (leaks) process.exitCode = 3;
  },
  // A filter: stdin → stdout with every kept value (and, with --patterns, every known key shape)
  // replaced by its name. For other tools that store or forward text an agent produced — a memory
  // that dreams transcripts, a log shipper — so a secret that slipped into a session stops there.
  async redact() {
    let text = '';
    process.stdin.setEncoding('utf8');
    for await (const c of process.stdin) text += c;
    let values = {};
    try { values = vault.status().initialised ? vault._values() : {}; } catch (e) { process.stderr.write(`keep: cannot open the vault (${e.message})\n`); }
    let r = redactText(text, needles(values));
    let n = r.count;
    if (flags.patterns) { const p = redactPatterns(r.text); r = p; n += p.count; }
    process.stdout.write(r.text);
    if (flags.count) process.stderr.write(`keep: ${n} redacted\n`);
  },
  // A Claude Code PreToolUse hook: refuse reading a secret file, and say what to do instead.
  // `keep guard --install` wires it into ~/.claude/settings.json; `--uninstall` takes it out.
  async guard() {
    if (flags.install || flags.uninstall) return out(installGuard(!!flags.uninstall));
    let raw = '';
    process.stdin.setEncoding('utf8');
    for await (const c of process.stdin) raw += c;
    let input = {};
    try { input = JSON.parse(raw); } catch { return; }
    const d = judge(input);
    if (d) out(JSON.stringify(d));
  },
  request() {
    const n = args[0];
    if (!n) die('usage: keep request NAME ["why you need it"]');
    vault.init();
    const r = vault.request(n, args.slice(1).join(' '));
    out(r.exists ? `${n} is already kept — use it: keep run --with ${n} -- …` : `asked for ${n}. Your person answers with: keep set ${n}`);
  },
  audit() {
    const rows = vault.auditLog(Number(flags.limit) || 30);
    if (!rows.length) return out('(nothing used yet)');
    for (const r of rows) out(`${r.when.slice(0, 19).replace('T', ' ')}  ${r.secrets.join(',').padEnd(24)} exit ${String(r.exit ?? r.signal ?? r.error).padEnd(4)} ${r.redactions ? `${r.redactions} redacted  ` : ''}${r.command}`);
  },
  status() {
    const s = vault.status();
    if (!s.initialised) return out(`no vault at ${s.home} — keep init`);
    out([
      `vault     ${s.home}`,
      `key       ${s.backend}${s.weak ? '  (a file beside the vault — weaker than a keychain; see README)' : ''}`,
      `opens     ${s.opens ? 'yes' : 'NO — the key is missing or the vault was altered'}`,
      `secrets   ${s.secrets}${s.requests.length ? `   requests waiting: ${s.requests.map((q) => q.name).join(', ')}` : ''}`,
    ].join('\n'));
  },
  async mcp() { await import(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'mcp', 'mcp-server.js')); },
  version() { out(JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version); },
  help() {
    out(`keep — use a secret without holding it

  keep init                                   create the vault (master key in the OS keychain)
  keep set NAME [--allow gh,curl] [--note ..]  store a value: piped on stdin, or typed hidden
  keep import .env [--allow ..]               keep every KEY=value in a dotenv file
  keep list                                   names, policy, usage — never values
  keep run [--with A,B] -- cmd args…          run with secrets injected as env vars; {{NAME}} in args
                                              is replaced; every kept value is redacted from output
  keep scan [paths…] [--transcripts]          find kept values (and known key shapes) that leaked
  keep redact [--patterns] < in > out         a filter: kept values (and key shapes) → their names
  keep guard [--install|--uninstall]          a Claude Code hook: refuse an agent READING a secret file (.env, *.pem…)
  keep request NAME ["why"]                   an agent asks its person for a secret it lacks
  keep audit [--limit N]                      every use: names, command, exit — never values
  keep status · keep rm NAME · keep mcp       vitals · forget one · the MCP server (stdio)

env: KEEP_HOME (vault dir, default ~/.keep) · KEEP_BACKEND (keychain | secret-tool | file) · KEEP_TRANSCRIPTS`);
  },
};

const fn = commands[{ '--help': 'help', '-h': 'help', '--version': 'version' }[cmd] || cmd];
if (!fn) { process.stderr.write(`keep: unknown command "${cmd}"\n\n`); commands.help(); process.exit(2); }
Promise.resolve().then(fn).catch((e) => die(e.message));

// --- helpers --------------------------------------------------------------------------------
function parse(list) {
  const args = [];
  const flags = {};
  for (let i = 0; i < list.length; i++) {
    const a = list[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = list[i + 1];
      if (v !== undefined && !v.startsWith('--')) { flags[k] = v; i++; } else flags[k] = true;
    } else args.push(a);
  }
  return { args, flags };
}

// Piped: read all of stdin. A terminal: prompt with echo off, so the value never hits the
// scrollback — and never the transcript of an agent watching this terminal.
function readSecret(prompt) {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    return new Promise((resolve) => { let d = ''; stdin.setEncoding('utf8'); stdin.on('data', (c) => { d += c; }); stdin.on('end', () => resolve(d)); });
  }
  return new Promise((resolve, reject) => {
    process.stderr.write(prompt);
    let v = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n' || c === '\u0004') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); process.stderr.write('\n'); return resolve(v); }
        if (c === '\u0003') { stdin.setRawMode(false); process.stderr.write('\n'); return reject(new Error('cancelled')); }
        if (c === '\u007f' || c === '\b') v = v.slice(0, -1); else v += c;
      }
    };
    stdin.on('data', onData);
  });
}

// settings.json surgery: add or remove ONLY our hook, keep everyone else's, back the file up first.
function installGuard(remove) {
  const file = process.env.KEEP_CLAUDE_SETTINGS || path.join(os.homedir(), '.claude', 'settings.json');
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* new file */ }
  const cmd = `node "${path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.js')}" guard`;
  cfg.hooks ||= {};
  const list = (cfg.hooks.PreToolUse ||= []);
  const ours = (h) => (h.hooks || []).some((x) => /keep[\\/]src[\\/]cli\.js"? guard|(^|\s)keep guard$/.test(x.command || ''));
  const kept = list.filter((h) => !ours(h));
  if (!remove) kept.push({ matcher: 'Bash|Read', hooks: [{ type: 'command', command: cmd }] });
  cfg.hooks.PreToolUse = kept;
  if (!kept.length) delete cfg.hooks.PreToolUse;
  if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.keep-bak`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(cfg, null, 2)}\n`);
  return remove ? `keep guard removed from ${file}` : `keep guard installed in ${file} (PreToolUse: Bash|Read) — a backup is at ${file}.keep-bak`;
}
