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

// `process.env`, `import.meta.env` are code, not files — and they are in every JS command an agent
// writes. The guard refused its own author on the first live day for `(env = process.env)`.
const CODE_NOT_FILE = /(^|\/)(?:process|import\.meta|os|self|window|globalThis|config|app|settings)\.env$/;

function secretIn(text) {
  const out = [];
  const re = new RegExp(SECRET_FILE.source, 'g');
  let m;
  while ((m = re.exec(String(text)))) {
    const f = m[2];
    if (!TEMPLATE.test(f) && !CODE_NOT_FILE.test(f)) out.push(f);
  }
  return out;
}

// A heredoc's BODY is data being written somewhere (a test, a script, a doc), not a command being
// run: `cat > test.js <<'EOF' … 'cat .env' … EOF` writes a test ABOUT .env and reads nothing. Only
// the command line around it is judged.
// But a heredoc fed to an INTERPRETER (`python3 <<EOF … open('.env') … EOF`) is code being run, and
// it stays: only a body headed for a file (`cat > f <<EOF`, `tee f <<EOF`) is skipped.
//
// And in code fed to an interpreter, only an actual READ counts. A python heredoc that edits a doc
// saying "never cat a .env" names the file in a string and reads nothing — and was refused, on the
// guard's second live day. open('.env'), readFileSync('.env'), load_dotenv(), a cat inside a
// subprocess: those are reads, and they stay.
// The file has to be what the read reads: inside the call's parentheses, the first argument of a
// cat-like command, or an argument after the pattern of a grep-like one — not merely on the same line.
const CALL_READ = /\b(?:open|readFile|readFileSync|read_text|read_bytes|load_dotenv|dotenv_values|fopen|File\.read|IO\.read)\s*\(([^)]*)/g;
const CAT_READ = /(?:^|[\s;&|(`$'"])(?:cat|head|tail|less|more|base64|xxd|strings)\s+(?:-\S+\s+)*(\S+)/g;
const GREP_READ = /(?:^|[\s;&|(`$'"])(?:grep|egrep|rg|sed|awk)\s+(?:-\S+\s+)*(?:'[^']*'|"[^"]*"|\S+)\s+((?:\S+\s*){1,3})/g;
const heredocBody = (body) => {
  const files = [];
  for (const line of body.split('\n')) {
    for (const re of [CALL_READ, CAT_READ, GREP_READ]) {
      for (const m of line.matchAll(re)) files.push(...secretIn(` ${m[1]} `));
    }
  }
  return files.length ? ` cat ${files.join(' ')} ` : ' ';
};
export const withoutHeredocs = (cmd) => String(cmd).replace(/([^\n]*?)<<-?\s*(['"]?)(\w+)\2([^\n]*)\n([\s\S]*?)\n\s*\3\s*(?=\n|$)/g,
  (whole, before, _q, _tag, after, body) => (/\b(cat|tee)\b[^|;&]*>|\btee\b/.test(`${before} ${after}`)
    ? `${before} ${after}`
    : `${before} ${after}${heredocBody(body)}`));

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
  const cmd = withoutHeredocs(ti.command || '');
  if (/(^|[\s;&|])keep\s+(import|set|run|redact|scan)\b/.test(cmd)) return null;
  // Writing TO a secret file (>> .env, > .env, tee .env) is not reading it: take the write targets out first.
  const reading = cmd.replace(/(\d?>>?|\btee(\s+-a)?)\s*['"]?[^\s'";|&)]+/g, ' ');
  if (!secretIn(reading).length) return null;
  // It must READ the file — and the reader and the file must be in the SAME command of a pipeline.
  // `ls -la ~/.npmrc | awk '{print $5}'` names the file in `ls` (which lists it) and reads a pipe in
  // `awk`; judged as one string it looked like "awk reads .npmrc" and was refused.
  const segments = splitCommands(reading);
  // …and the reader is the segment's COMMAND, not a word somewhere in its arguments: a commit message
  // that quotes `grep … backend/.env` is git, not grep (refused on the guard's third live day).
  // (git's diff/show/blame/grep/log -p print the content of the files they are given.)
  // An input redirection counts only when what follows `<` IS a secret file — not any `<` at all, which
  // matched the `<noreply@…>` at the end of every commit message this machine writes.
  const redirectsIn = (seg) => [...seg.matchAll(/(?:^|[^<])<(?!<)\s*(['"]?)([^\s'"<>]+)\1/g)].some((m) => secretIn(` ${m[2]} `).length);
  const reads = (seg) => READERS.test(` ${commandWord(seg)} `) || redirectsIn(seg)
    || (commandWord(seg) === 'git' && /^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:(?:sudo|env)\s+)*(?:\S*\/)?git\s+(?:-\S+\s+)*(diff|show|blame|grep|log|cat-file)\b/.test(seg));
  const files = segments.filter((seg) => secretIn(seg).length && reads(seg)).flatMap((seg) => secretIn(seg));
  if (!files.length) return null;
  return deny(files[0], files[0]);
}

// The word a segment runs: past VAR=value assignments and the wrappers that run another command.
export function commandWord(seg) {
  const words = String(seg).trim().split(/\s+/);
  let i = 0;
  while (i < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]) || /^(sudo|env|time|nice|nohup|command|exec|xargs|builtin)$/.test(words[i]) || (/^-/.test(words[i]) && i > 0))) i++;
  return (words[i] || '').replace(/^.*\//, '');
}

// Split a command line on | || && ; & and newlines — but never inside quotes: the leak this guard
// exists for was `grep -n "DATABASE_URL\|PG\|pg_" backend/.env`, whose pattern is full of pipes.
export function splitCommands(cmd) {
  const out = [];
  let cur = '', q = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (q) { cur += c; if (c === '\\' && q === '"') { cur += cmd[++i] || ''; } else if (c === q) q = null; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === '\\') { cur += c + (cmd[++i] || ''); continue; }
    if (c === '|' || c === ';' || c === '&' || c === '\n') { out.push(cur); cur = ''; if (cmd[i + 1] === c) i++; continue; }
    cur += c;
  }
  out.push(cur);
  return out;
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
