// Scan: has a kept secret already leaked?
//
// The place a secret goes to die is not the repo. It is the agent's own transcript: every
// `cat .env`, every `echo $TOKEN`, every verbose curl an agent ever ran is written, verbatim, to
// ~/.claude/projects/*.jsonl — and read again by whatever reads transcripts (a summariser, a
// dream, a search index). `keep scan --transcripts` looks there.
//
// Two kinds of finding, never mixed up:
//   kept     a value in YOUR vault, in any of its shapes (raw, encoded, base64 at any alignment).
//            Certain: that exact secret is in that file.
//   pattern  something SHAPED like a well-known key format (sk-…, ghp_…, AKIA…). A guess, and
//            reported as one — it may be a test fixture, an example, or revoked.
// A finding never prints the value. It prints where, and which name.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { needles } from './redact.js';

export const PATTERNS = [
  ['anthropic', /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ['openai', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g],
  ['github', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['slack', /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ['stripe', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g],
  ['google-api', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['npm', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
];

const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', '__pycache__', '.next', 'dist', 'build', '.godot', '.cache']);
const MAX_FILE = 50 * 1024 * 1024;

export const transcriptsDir = () => process.env.KEEP_TRANSCRIPTS || path.join(os.homedir(), '.claude', 'projects');

function* walk(root) {
  let st;
  try { st = fs.statSync(root); } catch { return; }
  if (st.isFile()) { yield root; return; }
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); } else if (e.isFile()) yield p;
    }
  }
}

// A value shorter than this is too short to be a key; "hint: AKIA… in a README" is a pattern
// finding, and the preview keeps only enough to recognise it.
const preview = (s) => `${s.slice(0, 6)}…(${s.length} chars)`;

export function scan(roots, values = {}, { patterns = true, limit = 500 } = {}) {
  const list = needles(values);
  const findings = [];
  let files = 0;
  let bytes = 0;
  for (const root of roots) {
    for (const file of walk(root)) {
      if (findings.length >= limit) break;
      let st;
      try { st = fs.statSync(file); } catch { continue; }
      if (st.size > MAX_FILE || st.size === 0) continue;
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
      if (text.includes('\u0000')) continue; // binary
      files++;
      bytes += st.size;
      const lines = text.split('\n');
      const seen = new Set();
      for (let i = 0; i < lines.length && findings.length < limit; i++) {
        const line = lines[i];
        for (const { name, needle } of list) {
          if (line.includes(needle) && !seen.has(`k:${name}:${i}`)) {
            seen.add(`k:${name}:${i}`);
            findings.push({ kind: 'kept', name, file, line: i + 1, shape: needle === values[name] ? 'raw' : 'encoded' });
          }
        }
        if (!patterns) continue;
        for (const [label, re] of PATTERNS) {
          for (const m of line.matchAll(re)) {
            if (Object.values(values).some((v) => String(v).includes(m[0]) || m[0].includes(String(v)))) continue; // already a kept finding
            if (seen.has(`p:${m[0]}`)) continue;
            seen.add(`p:${m[0]}`);
            findings.push({ kind: 'pattern', name: label, file, line: i + 1, preview: preview(m[0]) });
          }
        }
      }
    }
  }
  return { files, bytes, findings, truncated: findings.length >= limit };
}

// One line per (file, name): a transcript that echoed a token forty times is one leak to fix.
export function summarise(findings) {
  const groups = new Map();
  for (const f of findings) {
    const k = `${f.kind}\u0000${f.name}\u0000${f.file}`;
    const g = groups.get(k) || { kind: f.kind, name: f.name, file: f.file, lines: [], preview: f.preview };
    g.lines.push(f.line);
    groups.set(k, g);
  }
  return [...groups.values()].sort((a, b) => (a.kind === b.kind ? a.file.localeCompare(b.file) : a.kind === 'kept' ? -1 : 1));
}

// For `keep redact --patterns`: a key SHAPE has no name in the vault, so it becomes its kind.
// A private key is a BLOCK: masking its BEGIN line and leaving the body would redact the label and
// hand over the key. So the whole block goes — through END if it is there, and through the whole
// run of base64 (with real or JSON-escaped newlines) if the text was cut off before it.
const KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|(?:\\n|\\r|\s|[A-Za-z0-9+/=])*)/g;
export function redactPatterns(text) {
  let count = 0;
  let s = String(text).replace(KEY_BLOCK, () => { count++; return '‹keep:private-key›'; });
  for (const [label, re] of PATTERNS) s = s.replace(re, () => { count++; return `‹keep:${label}›`; });
  return { text: s, count };
}
