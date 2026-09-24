// guard: a Claude Code PreToolUse hook that stops an agent READING a secret file.
//
// keep lets an agent use a secret without holding it — but nothing stopped it from holding one
// anyway. The leak keep's first scan found was exactly that: an agent looking for a database URL ran
// `grep -n "…\|PG\|…" backend/.env`, the base64 body of a Firebase private key happened to contain
// "PG", and the key went into the transcript. No intent, no attack — a grep.
//
// So: a Bash command that reads a secret-bearing file (cat, grep, head, tail, less, sed, awk, cut,
// strings, xxd, base64, source…), or a Read of one, is refused — and the refusal carries the way
// forward, which an agent can take on its own with no human awake: `keep import <file>` stores every
// value without printing one, then `keep run --with NAME -- <cmd>` uses it.
//
// What is NOT refused: templates (.env.example / .sample / .template / .dist), keep's own commands,
// writing to a secret file, and what names one without PRINTING it: ls, test -f, mv, cp .env.example
// .env, `source .env && npm start` (loading a file into a process is how it is meant to be used).
import path from 'node:path';

const SECRET_FILE = /(^|[\s/'"=<(@])((?:[\w.-]*\/)*(?:\.env(?:\.[\w-]+)?|[\w.-]+\.env|[\w.-]*\.(?:pem|key|p12|pfx|keystore|jks)|id_(?:rsa|ed25519|ecdsa|dsa)|credentials(?:\.json)?|[\w.-]*service[-_]?account[\w.-]*\.json|\.netrc|\.pgpass|\.npmrc|\.pypirc))(?=$|[\s'")|;&>])/;
const TEMPLATE = /\.(?:example|sample|template|dist|defaults?)$|\.example\./i;
const READERS = /(^|[\s;&|(`$])(cat|bat|less|more|head|tail|grep|egrep|fgrep|rg|ag|sed|awk|cut|sort|uniq|strings|xxd|hexdump|od|base64|openssl|jq|yq|nl|tac|paste|diff|cmp|column|tr|python3?|node|ruby|perl|curl|nc)(?=\s)/;

function secretIn(text) {
  const out = [];
  const re = new RegExp(SECRET_FILE.source, 'g');
  let m;
  while ((m = re.exec(String(text)))) {
    const f = m[2];
    if (!TEMPLATE.test(f)) out.push(f);
  }
  return out;
}

export function judge(input = {}) {
  const tool = input.tool_name || '';
  const ti = input.tool_input || {};
  if (tool === 'Read' || tool === 'NotebookRead') {
    const f = ti.file_path || ti.notebook_path || '';
    const base = path.basename(f);
    if (secretIn(` ${base} `).length) return deny(base, f);
    return null;
  }
  if (tool !== 'Bash') return null;
  const cmd = String(ti.command || '');
  if (/(^|[\s;&|])keep\s+(import|set|run|redact|scan)\b/.test(cmd)) return null;
  // Writing TO a secret file (>> .env, > .env, tee .env) is not reading it: take the write targets out first.
  const reading = cmd.replace(/(\d?>>?|\btee(\s+-a)?)\s*['"]?[^\s'";|&)]+/g, ' ');
  const files = secretIn(reading);
  if (!files.length) return null;
  // It must READ the file: a reader in the command, or an input redirection from it.
  if (!READERS.test(reading) && !/<\s*['"]?[^\s'"]*/.test(reading)) return null;
  return deny(files[0], files[0]);
}

function deny(name, full) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason:
        `keep guard: ${name} holds secrets, and reading it puts them into this transcript (and everything that reads transcripts later). `
        + `Do this instead — no human needed: \`keep import ${full}\` stores every value without printing one; \`keep list\` shows the names; `
        + `then \`keep run --with NAME -- <command>\` (or {{NAME}} in an argument) uses a value without you ever seeing it. `
        + `If you only need a non-secret setting from it (a port, a hostname), ask your person, or read it from a template (.env.example).`,
    },
  };
}
