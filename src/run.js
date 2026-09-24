// Running a command WITH secrets, without the caller ever holding them.
//
// The named secrets go into the child's environment (and into any {{NAME}} in its argv); the
// child's stdout and stderr come back through a redactor built from EVERY kept value — not only
// the ones injected, because a secret the command found on its own (a config file, a keyring) is
// still a secret. The caller sees ‹keep:NAME› where the value would have been.
//
// Policy: each secret has an allow-list of command names. A secret allowed only to `gh` cannot
// be handed to `sh -c` or `node -e`, which is exactly the move an agent that has been talked into
// exfiltrating it would make.
import path from 'node:path';
import { spawn } from 'node:child_process';
import * as vault from './vault.js';
import { needles, redactor, redactText } from './redact.js';

const PLACEHOLDER = /\{\{([A-Z_][A-Z0-9_]*)\}\}/g;
const CAP = 100_000;

export function referenced(argv) {
  const names = new Set();
  for (const a of argv) for (const m of String(a).matchAll(PLACEHOLDER)) names.add(m[1]);
  return [...names];
}

export function plan({ argv, with: withNames = [] }) {
  if (!Array.isArray(argv) || !argv.length || !argv[0]) throw new Error('nothing to run — give a command after --');
  const names = [...new Set([...withNames, ...referenced(argv)])];
  for (const n of names) vault.checkName(n);
  const meta = Object.fromEntries(vault.list().map((s) => [s.name, s]));
  const cmd = path.basename(String(argv[0]));
  for (const n of names) {
    if (!meta[n]) throw new Error(`no secret named ${n} — \`keep list\` shows what exists; \`keep request ${n}\` asks your person for it`);
    const allow = meta[n].allow || ['*'];
    // A restricted secret goes only to a program found by NAME on the PATH: `./gh` is whatever
    // file sits in the working directory under that name, and a basename check would wave it through.
    if (!allow.includes('*') && String(argv[0]).includes('/')) {
      throw new Error(`${n} is restricted to ${allow.join(', ')}; run it by name (\`${cmd}\`), not by path (\`${argv[0]}\`)`);
    }
    if (!allow.includes('*') && !allow.includes(cmd)) {
      throw new Error(`${n} may only be used by: ${allow.join(', ')} — not by \`${cmd}\`. (A secret allowed to one program cannot be handed to a shell or an interpreter instead.)`);
    }
  }
  return { names, cmd };
}

// mode 'stream': pipe to the given writables as it happens (the CLI).
// mode 'collect': return { stdout, stderr } capped (MCP).
export async function run({ argv, with: withNames = [], cwd = process.cwd(), stdin, timeoutMs = 120_000, mode = 'collect', out = process.stdout, err = process.stderr }) {
  const { names, cmd } = plan({ argv, with: withNames });
  const all = vault._values();
  const injected = Object.fromEntries(names.map((n) => [n, all[n]]));
  const real = argv.map((a) => String(a).replace(PLACEHOLDER, (_, n) => injected[n]));
  const list = needles(all);
  const started = Date.now();
  return new Promise((resolve) => {
    const streams = { stdout: redactor(list), stderr: redactor(list) };
    const bufs = { stdout: '', stderr: '' };
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      const redactions = streams.stdout.count + streams.stderr.count;
      const result = {
        command: redactText(argv.join(' '), list).text,
        secrets: names,
        exit: r.exit ?? null,
        ...(r.signal ? { signal: r.signal } : {}),
        ...(r.error ? { error: r.error } : {}),
        redactions,
        ms: Date.now() - started,
        ...(mode === 'collect' ? { stdout: bufs.stdout, stderr: bufs.stderr, truncated: bufs.stdout.length >= CAP || bufs.stderr.length >= CAP } : {}),
      };
      try {
        vault.recordUse(names);
        vault.audit({ secrets: names, cmd, command: result.command, cwd, exit: result.exit, signal: result.signal || null, error: result.error || null, redactions });
      } catch (e) { result.audit = `NOT RECORDED: ${e.message}`; }
      resolve(result);
    };
    const sink = (which, text) => {
      if (!text) return;
      if (mode === 'stream') (which === 'stdout' ? out : err).write(text);
      else if (bufs[which].length < CAP) bufs[which] += text.slice(0, CAP - bufs[which].length);
    };
    let child;
    try {
      child = spawn(real[0], real.slice(1), { cwd, env: { ...process.env, ...injected }, stdio: [stdin === 'inherit' ? 'inherit' : 'pipe', 'pipe', 'pipe'] });
    } catch (e) { return finish({ error: e.message }); }
    for (const which of ['stdout', 'stderr']) {
      child[which].setEncoding('utf8');
      child[which].on('data', (c) => sink(which, streams[which].push(c)));
    }
    if (child.stdin) { child.stdin.on('error', () => { /* the child closed stdin early; not our failure */ }); child.stdin.end(typeof stdin === 'string' ? stdin : undefined); }
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.on('error', (e) => { clearTimeout(timer); finish({ error: e.code === 'ENOENT' ? `command not found: ${cmd}` : e.message }); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      for (const which of ['stdout', 'stderr']) sink(which, streams[which].end());
      finish({ exit: code, signal: timedOut ? 'timeout' : signal || null });
    });
  });
}
