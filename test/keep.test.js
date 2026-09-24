import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keep-test-'));
process.env.KEEP_HOME = path.join(dir, 'vault');
process.env.KEEP_BACKEND = 'file';
const vault = await import('../src/vault.js');
const { run } = await import('../src/run.js');
const { needles, redactText, redactor, mark } = await import('../src/redact.js');
const { scan, summarise } = await import('../src/scan.js');

const SECRET = 'sk-test-9f8e7d6c5b4a3210ZYXW';
const OTHER = 'hunter2-but-longer-ok';
const CLI = new URL('../src/cli.js', import.meta.url).pathname;
const MCP = new URL('../mcp/mcp-server.js', import.meta.url).pathname;
const everything = () => fs.readdirSync(process.env.KEEP_HOME).map((f) => fs.readFileSync(path.join(process.env.KEEP_HOME, f), 'utf8')).join('\n');

vault.init();
vault.set('API_KEY', SECRET);
vault.set('GH_ONLY', OTHER, { allow: 'gh,node' });

// --- the vault ---------------------------------------------------------------------------
test('no file in the vault holds a value in the clear', () => {
  const all = everything().replace(fs.readFileSync(path.join(process.env.KEEP_HOME, 'master.key'), 'utf8'), '');
  assert.ok(!all.includes(SECRET) && !all.includes(OTHER));
  assert.ok(!all.includes(Buffer.from(SECRET).toString('base64')));
});

test('vault files are private to the user', () => {
  for (const f of ['secrets.enc', 'index.json', 'master.key']) {
    assert.equal(fs.statSync(path.join(process.env.KEEP_HOME, f)).mode & 0o077, 0, `${f} is readable by others`);
  }
});

test('list gives names and policy, never values', () => {
  const l = vault.list();
  assert.deepEqual(l.map((s) => s.name), ['API_KEY', 'GH_ONLY']);
  assert.deepEqual(l[1].allow, ['gh', 'node']);
  assert.ok(!JSON.stringify(l).includes(SECRET));
});

test('an altered vault refuses to open instead of returning garbage', () => {
  const f = path.join(process.env.KEEP_HOME, 'secrets.enc');
  const good = fs.readFileSync(f, 'utf8');
  const blob = JSON.parse(good);
  const bytes = Buffer.from(blob.data, 'base64'); bytes[0] ^= 1;
  fs.writeFileSync(f, JSON.stringify({ ...blob, data: bytes.toString('base64') }));
  assert.throws(() => vault._values(), /did not decrypt/);
  assert.equal(vault.status().opens, false);
  fs.writeFileSync(f, good);
  assert.equal(vault.status().opens, true);
});

test('names must be env-var names; short values are refused because they cannot be redacted', () => {
  assert.throws(() => vault.set('api-key', SECRET), /UPPER_SNAKE_CASE/);
  assert.throws(() => vault.set('SHORT', 'abc'), /cannot be redacted safely/);
});

// --- redaction ---------------------------------------------------------------------------
test('redacts the raw value, and its JSON, URL and base64 shapes', () => {
  const list = needles({ API_KEY: SECRET, P: 'p@ss/word "quoted"' });
  assert.equal(redactText(`key=${SECRET}`, list).text, `key=${mark('API_KEY')}`);
  assert.doesNotMatch(redactText(encodeURIComponent('p@ss/word "quoted"'), list).text, /p%40ss/);
  assert.doesNotMatch(redactText(JSON.stringify({ v: 'p@ss/word "quoted"' }), list).text, /ss\/word/);
  // A Basic auth header is base64("user:" + secret) — the secret at an arbitrary byte offset.
  for (const user of ['', 'a:', 'ab:', 'abc:', 'fatih:']) {
    const header = `Authorization: Basic ${Buffer.from(user + SECRET).toString('base64')}`;
    const r = redactText(header, list);
    assert.ok(r.count >= 1, `base64 after "${user}" leaked: ${header}`);
    assert.ok(r.text.length < header.length / 2 + 30, `most of the header is the secret, so most of it must be gone: ${r.text}`);
  }
  assert.ok(redactText(Buffer.from(SECRET).toString('base64url'), list).count >= 1, 'base64url too');
});

test('a value split across stream chunks is still redacted, at every split point', () => {
  const list = needles({ API_KEY: SECRET });
  const text = `before ${SECRET} after`;
  for (let cut = 0; cut <= text.length; cut++) {
    const r = redactor(list);
    const got = r.push(text.slice(0, cut)) + r.push(text.slice(cut)) + r.end();
    assert.equal(got, `before ${mark('API_KEY')} after`, `split at ${cut}`);
  }
});

// --- run ---------------------------------------------------------------------------------
test('run injects the secret as an env var and the caller only sees its name', async () => {
  const r = await run({ argv: ['node', '-e', 'console.log("got " + process.env.API_KEY)'], with: ['API_KEY'] });
  assert.equal(r.exit, 0);
  assert.equal(r.stdout.trim(), `got ${mark('API_KEY')}`);
  assert.equal(r.redactions, 1);
});

test('{{NAME}} in an argument is replaced, and injected without --with', async () => {
  const r = await run({ argv: ['node', '-e', 'console.log(process.argv[1].length, process.env.API_KEY === process.argv[1])', '{{API_KEY}}'] });
  assert.equal(r.stdout.trim(), `${SECRET.length} true`);
  assert.deepEqual(r.secrets, ['API_KEY']);
  assert.ok(!r.command.includes(SECRET));
});

test('every kept value is redacted, not only the injected ones', async () => {
  const f = path.join(dir, 'config.txt');
  fs.writeFileSync(f, `token: ${OTHER}\n`);
  const r = await run({ argv: ['cat', f] });
  assert.equal(r.stdout.trim(), `token: ${mark('GH_ONLY')}`);
});

test('stderr is redacted, and the exit code comes back', async () => {
  const r = await run({ argv: ['node', '-e', 'console.error(process.env.API_KEY); process.exit(7)'], with: ['API_KEY'] });
  assert.equal(r.exit, 7);
  assert.equal(r.stderr.trim(), mark('API_KEY'));
});

test('a restricted secret cannot be handed to a shell, an unlisted program, or a look-alike path', async () => {
  await assert.rejects(run({ argv: ['sh', '-c', 'echo $GH_ONLY'], with: ['GH_ONLY'] }), /may only be used by: gh, node/);
  await assert.rejects(run({ argv: ['curl', 'https://example.com/?k={{GH_ONLY}}'] }), /not by `curl`/);
  fs.writeFileSync(path.join(dir, 'gh'), '#!/bin/sh\necho "$GH_ONLY"\n', { mode: 0o755 });
  await assert.rejects(run({ argv: ['./gh'], with: ['GH_ONLY'], cwd: dir }), /run it by name/);
  const ok = await run({ argv: ['node', '-e', 'process.stdout.write(String(process.env.GH_ONLY.length))'], with: ['GH_ONLY'] });
  assert.equal(ok.stdout, String(OTHER.length));
});

test('an unknown secret is an error that says how to get it', async () => {
  await assert.rejects(run({ argv: ['node', '-e', '1'], with: ['NOPE_KEY'] }), /keep request NOPE_KEY/);
});

test('the audit log records every use and never a value', async () => {
  await run({ argv: ['node', '-e', 'console.log(process.env.API_KEY)', '{{API_KEY}}'] });
  const log = vault.auditLog();
  const last = log.at(-1);
  assert.deepEqual(last.secrets, ['API_KEY']);
  assert.equal(last.cmd, 'node');
  assert.ok(last.redactions >= 1);
  assert.ok(!fs.readFileSync(path.join(process.env.KEEP_HOME, 'audit.jsonl'), 'utf8').includes(SECRET));
  assert.ok(vault.list().find((s) => s.name === 'API_KEY').uses >= 1);
});

test('a raw value typed into the command itself is redacted from the result and the log', async () => {
  const r = await run({ argv: ['node', '-e', 'console.log(1)', SECRET] });
  assert.ok(!r.command.includes(SECRET));
  assert.ok(!fs.readFileSync(path.join(process.env.KEEP_HOME, 'audit.jsonl'), 'utf8').includes(SECRET));
});

test('a runaway command is killed at the timeout', async () => {
  const r = await run({ argv: ['node', '-e', 'setInterval(()=>{}, 1000)'], timeoutMs: 300 });
  assert.equal(r.signal, 'timeout');
});

test('a missing program is reported, not thrown', async () => {
  const r = await run({ argv: ['definitely-not-a-command-xyz'] });
  assert.match(r.error, /command not found/);
});

// --- scan --------------------------------------------------------------------------------
test('scan finds a kept value in any shape, and a known key shape as a guess — never printing either', () => {
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(path.join(repo, 'node_modules'), { recursive: true });
  fs.writeFileSync(path.join(repo, '.env'), `API_KEY=${SECRET}\n`);
  fs.writeFileSync(path.join(repo, 'log.jsonl'), `{"h":"Basic ${Buffer.from(`me:${SECRET}`).toString('base64')}"}\n`);
  fs.writeFileSync(path.join(repo, 'notes.md'), 'old key ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 revoked\n');
  fs.writeFileSync(path.join(repo, 'node_modules', 'x.js'), SECRET);
  const r = scan([repo], vault._values());
  const g = summarise(r.findings);
  const kept = g.filter((x) => x.kind === 'kept').map((x) => path.basename(x.file)).sort();
  assert.deepEqual(kept, ['.env', 'log.jsonl']);
  const guess = g.find((x) => x.kind === 'pattern');
  assert.equal(guess.name, 'github');
  assert.match(guess.preview, /^ghp_AB…\(40 chars\)$/);
  assert.ok(!JSON.stringify(g).includes(SECRET) && !JSON.stringify(g).includes('ghp_ABCDEFGHIJ'));
});

// --- the interfaces ----------------------------------------------------------------------
const env = { ...process.env };
test('CLI: set from stdin, run passes the exit code through and redacts', () => {
  let r = spawnSync(process.execPath, [CLI, 'set', 'CLI_KEY'], { input: 'cli-secret-value-123\n', encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stderr);
  r = spawnSync(process.execPath, [CLI, 'run', '--with', 'CLI_KEY', '--', 'node', '-e', 'console.log(process.env.CLI_KEY); process.exit(4)'], { encoding: 'utf8', env });
  assert.equal(r.status, 4);
  assert.equal(r.stdout.trim(), mark('CLI_KEY'));
  assert.match(r.stderr, /1 secret value redacted/);
  r = spawnSync(process.execPath, [CLI, 'list'], { encoding: 'utf8', env });
  assert.match(r.stdout, /CLI_KEY/);
  assert.ok(!r.stdout.includes('cli-secret-value-123'));
});

test('MCP: keep_run redacts, and nothing in the whole conversation carries a value', () => {
  const msgs = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'keep_run', arguments: { command: ['node', '-e', 'console.log(process.env.API_KEY)'], with: ['API_KEY'] } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'keep_list', arguments: {} } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'keep_request', arguments: { name: 'STRIPE_KEY', why: 'to test the checkout' } } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'keep_audit', arguments: {} } },
    { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'keep_scan', arguments: { paths: [path.join(dir, 'repo')] } } },
  ];
  const r = spawnSync(process.execPath, [MCP], { input: msgs.map((m) => JSON.stringify(m)).join('\n') + '\n', encoding: 'utf8', env, timeout: 20000 });
  const replies = r.stdout.trim().split('\n').map((l) => JSON.parse(l));
  const names = replies.find((x) => x.id === 2).result.tools.map((t) => t.name);
  assert.ok(!names.some((n) => /get|read|reveal|export/.test(n)), `a tool that could return a value exists: ${names}`);
  const ran = JSON.parse(replies.find((x) => x.id === 3).result.content[0].text);
  assert.equal(ran.stdout.trim(), mark('API_KEY'));
  assert.match(replies.find((x) => x.id === 5).result.content[0].text, /keep set STRIPE_KEY/);
  assert.ok(vault.status().requests.some((q) => q.name === 'STRIPE_KEY'));
  for (const v of [SECRET, OTHER, 'cli-secret-value-123']) assert.ok(!r.stdout.includes(v), 'a value crossed the MCP boundary');
});

test('a request is answered by the secret arriving', () => {
  vault.set('STRIPE_KEY', 'sk_test_abcdefghijklmnop');
  assert.ok(!vault.status().requests.some((q) => q.name === 'STRIPE_KEY'));
});

test('redact: a filter other tools can pipe text through', () => {
  const input = `said ${SECRET} and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 and ${Buffer.from(`u:${OTHER}`).toString('base64')}`;
  let r = spawnSync(process.execPath, [CLI, 'redact'], { input, encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes(SECRET) && r.stdout.includes(mark('API_KEY')));
  assert.ok(r.stdout.includes('ghp_ABCDEF'), 'a shape is left alone without --patterns');
  r = spawnSync(process.execPath, [CLI, 'redact', '--patterns', '--count'], { input, encoding: 'utf8', env });
  assert.ok(r.stdout.includes('‹keep:github›') && !r.stdout.includes('ghp_ABCDEF'));
  assert.match(r.stderr, /3 redacted/);
});

test('redact --patterns takes a private key whole, not just its label', () => {
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC03EoDMHbnkCiD';
  for (const input of [
    `x -----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY----- y`,
    JSON.stringify({ env: `FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n"` }),
    `cut off: -----BEGIN RSA PRIVATE KEY-----\n${body}`,
  ]) {
    const r = spawnSync(process.execPath, [CLI, 'redact', '--patterns'], { input, encoding: 'utf8', env });
    assert.ok(!r.stdout.includes('MIIEvQ') && !r.stdout.includes('03EoDM'), `the key body survived: ${r.stdout}`);
    assert.match(r.stdout, /‹keep:private-key›/);
  }
});
