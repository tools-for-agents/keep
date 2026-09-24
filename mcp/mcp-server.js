#!/usr/bin/env node
// keep — MCP server (stdio JSON-RPC). Lets an agent USE a secret without ever holding it: the
// value is injected into the command it runs and redacted from everything that comes back.
// There is no tool that returns a value. That is not an omission; it is the design.
import { createInterface } from 'node:readline';
import * as vault from '../src/vault.js';
import { run } from '../src/run.js';
import { scan, summarise, transcriptsDir } from '../src/scan.js';

const PROTOCOL = '2024-11-05';

const tools = [
  {
    name: 'keep_list',
    description: 'List the secrets kept for you — names, which commands may use each, and how often they were used. Never values. Also lists secrets you asked for that your person has not added yet.',
    inputSchema: { type: 'object', properties: {} },
    run: () => { const s = vault.status(); return s.initialised ? { secrets: vault.list(), requests: s.requests } : { secrets: [], requests: [], note: 'no vault yet — your person runs: keep init' }; },
  },
  {
    name: 'keep_run',
    description: 'Run a command WITH secrets you never see. Named secrets are injected as environment variables, and {{NAME}} inside any argument is replaced by the value. Every kept value is redacted from stdout/stderr as ‹keep:NAME› — including base64 and URL-encoded forms. Use this instead of reading a .env or a token: e.g. command ["gh","api","user"] with ["GH_TOKEN"], or ["curl","-H","Authorization: Bearer {{OPENAI_API_KEY}}","https://…"].',
    inputSchema: { type: 'object', properties: {
      command: { type: 'array', items: { type: 'string' }, description: 'argv — the program and its arguments, not a shell string. {{NAME}} is replaced by the secret.' },
      with: { type: 'array', items: { type: 'string' }, description: 'Secret names to inject as env vars (secrets named in {{…}} are injected automatically)' },
      cwd: { type: 'string', description: 'Working directory (default: the server\'s)' },
      stdin: { type: 'string', description: 'Text piped to the command' },
      timeout_ms: { type: 'integer', description: 'Max runtime (default 120000, max 1800000)' },
    }, required: ['command'] },
    run: (a) => run({ argv: a.command, with: a.with || [], cwd: a.cwd || process.cwd(), stdin: a.stdin, timeoutMs: Math.min(Math.max(Number(a.timeout_ms) || 120000, 1000), 1800000) }),
  },
  {
    name: 'keep_scan',
    description: 'Check whether a kept secret has leaked into files — a repo, a log, or (transcripts: true) your own Claude Code transcripts. Reports file, line and secret NAME, never the value; also flags strings shaped like well-known keys (sk-…, ghp_…, AKIA…) as "pattern" findings, which are guesses.',
    inputSchema: { type: 'object', properties: {
      paths: { type: 'array', items: { type: 'string' }, description: 'Files or directories to scan' },
      transcripts: { type: 'boolean', description: 'Also scan ~/.claude/projects (every agent transcript on this machine)' },
      patterns: { type: 'boolean', description: 'Also report known key shapes (default true)' },
    } },
    run: (a) => {
      const roots = [...(a.paths || [])];
      if (a.transcripts) roots.push(transcriptsDir());
      if (!roots.length) roots.push(process.cwd());
      const values = vault.status().initialised ? vault._values() : {};
      const r = scan(roots, values, { patterns: a.patterns !== false });
      return { files: r.files, bytes: r.bytes, truncated: r.truncated, findings: summarise(r.findings) };
    },
  },
  {
    name: 'keep_request',
    description: 'Ask your person for a secret you need but do not have. It appears in their `keep list` and is answered when they run `keep set NAME`. Never ask them to paste a secret into the chat — ask here instead.',
    inputSchema: { type: 'object', properties: {
      name: { type: 'string', description: 'UPPER_SNAKE_CASE name, the env var it will become' },
      why: { type: 'string', description: 'One line: what you need it for' },
    }, required: ['name'] },
    run: (a) => { vault.init(); const r = vault.request(a.name, a.why || ''); return r.exists ? { exists: true, use: `keep_run with ["${a.name}"]` } : { requested: a.name, tell_them: `Please run in a terminal: keep set ${a.name}` }; },
  },
  {
    name: 'keep_audit',
    description: 'The log of every secret use: when, which names, which command, exit code, how many values were redacted. Never values.',
    inputSchema: { type: 'object', properties: { limit: { type: 'integer', description: 'How many recent entries (default 30)' } } },
    run: (a) => vault.auditLog(Number(a.limit) || 30),
  },
];

const ANNOTATIONS = {
  keep_list: { readOnlyHint: true, openWorldHint: false },
  keep_audit: { readOnlyHint: true, openWorldHint: false },
  keep_scan: { readOnlyHint: true, openWorldHint: false },
  keep_request: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  keep_run: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
};

const toolMap = Object.fromEntries(tools.map((t) => [t.name, t]));
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const fail = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

async function handle(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize')
    return reply(id, { protocolVersion: PROTOCOL, capabilities: { tools: {} },
      serverInfo: { name: 'keep', version: '0.1.0' } });
  if (method === 'notifications/initialized' || method === 'notifications/cancelled') return;
  if (method === 'ping') return reply(id, {});
  if (method === 'tools/list')
    return reply(id, { tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema, annotations: ANNOTATIONS[name] })) });
  if (method === 'tools/call') {
    const tool = toolMap[params?.name];
    if (!tool) return fail(id, -32602, `unknown tool: ${params?.name}`);
    // Every tool DECLARES its required arguments in inputSchema, and nothing enforced
    // them. `lens_search` with no query did not say "query is required" — it called
    // search(undefined) and died three layers down with
    //     Cannot read properties of undefined (reading 'match')
    // which is what a model got back, as if it were an answer. A schema that promises a
    // check nobody performs is worse than no schema: the client trusts it.
    const args = params?.arguments || {};
    const missing = (tool.inputSchema?.required || [])
      .filter((k) => args[k] === undefined || args[k] === null || args[k] === '');
    if (missing.length) {
      const how = missing
        .map((k) => `"${k}"${tool.inputSchema.properties?.[k]?.description ? ` (${tool.inputSchema.properties[k].description})` : ''}`)
        .join(', ');
      return fail(id, -32602, `${tool.name}: missing required argument${missing.length > 1 ? 's' : ''} ${how}`);
    }
    // ...and the TYPES it declares, and the enums. Nothing enforced those either, and
    // unlike a missing argument they do not crash — they corrupt, quietly:
    //   kanban_create_task labels:"urgent"   → a task whose labels are the letters u,r,g…
    //   cortex_write title:{...}             → a note on disk called "[object Object]"
    //   lens_search k:"eight"                → silently ignored, and you never learn why
    // Wrong data written confidently is worse than an error, because nothing announces it.
    const props = tool.inputSchema?.properties || {};
    const kindOf = (v) => (Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v);
    const OK = {
      string: (v) => typeof v === 'string',
      number: (v) => typeof v === 'number' && Number.isFinite(v),
      integer: (v) => Number.isInteger(v),
      boolean: (v) => typeof v === 'boolean',
      array: (v) => Array.isArray(v),
      object: (v) => v !== null && typeof v === 'object' && !Array.isArray(v),
    };
    const wrong = [];
    for (const [k, spec] of Object.entries(props)) {
      const v = args[k];
      if (v === undefined || v === null) continue;
      if (spec.type && OK[spec.type] && !OK[spec.type](v)) {
        wrong.push(`"${k}" must be ${spec.type}, got ${kindOf(v)}`);
      } else if (spec.enum && !spec.enum.includes(v)) {
        wrong.push(`"${k}" must be one of ${spec.enum.join(' | ')} — got ${JSON.stringify(v)}`);
      }
    }
    if (wrong.length) return fail(id, -32602, `${tool.name}: ${wrong.join('; ')}`);
    try {
      const out = await tool.run(args);
      return reply(id, { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    } catch (err) {
      return reply(id, { content: [{ type: 'text', text: `error: ${err.message}` }], isError: true });
    }
  }
  if (id !== undefined) fail(id, -32601, `method not found: ${method}`);
}

createInterface({ input: process.stdin }).on('line', (line) => {
  line = line.trim(); if (!line) return;
  let msg; try { msg = JSON.parse(line); } catch { return; }
  handle(msg).catch((e) => { if (msg.id !== undefined) fail(msg.id, -32603, String(e)); });
});
process.stderr.write('keep MCP server ready\n');
