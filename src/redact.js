// Redaction: every way a kept value can show up in text, replaced by its NAME.
//
// A secret leaks in more shapes than its own. `curl -v` prints an Authorization header, and a
// Basic header is base64("user:" + secret): the secret's bytes, shifted, in another alphabet. A
// redactor that only looks for the raw string hands that straight back. So each value becomes a
// set of needles:
//
//   raw · JSON-escaped · URL-encoded · base64 and base64url at all three byte alignments
//
// The alignment matters: base64 encodes three bytes at a time, so the secret's encoding depends
// on how many bytes came before it. Encoding it after 0, 1 and 2 bytes of padding, and keeping
// only the characters that depend on the secret alone, finds it inside ANY base64 string.
//
// Streaming: a needle can be split across two chunks. The redactor holds back the last
// (longest needle − 1) characters until more arrives, so nothing leaks through a seam.
export const mark = (name) => `‹keep:${name}›`;
const MIN_NEEDLE = 8;

function base64Needles(value) {
  const bytes = Buffer.from(value, 'utf8');
  const out = [];
  for (let k = 0; k < 3; k++) {
    const enc = Buffer.concat([Buffer.alloc(k), bytes]).toString('base64').replace(/=+$/, '');
    const start = [0, 2, 3][k];
    const end = (k + bytes.length) % 3 === 0 ? enc.length : enc.length - 1; // the last char mixes with what follows
    const core = enc.slice(start, end);
    if (core.length >= MIN_NEEDLE) out.push(core, core.replace(/\+/g, '-').replace(/\//g, '_'));
  }
  return out;
}

export function needles(values) {
  const list = [];
  for (const [name, value] of Object.entries(values)) {
    const v = String(value);
    const forms = new Set([v, JSON.stringify(v).slice(1, -1), encodeURIComponent(v), ...base64Needles(v)]);
    for (const n of forms) if (n && (n === v || n.length >= MIN_NEEDLE)) list.push({ name, needle: n });
  }
  // Longest first: a value that contains another value must be replaced whole.
  return list.sort((a, b) => b.needle.length - a.needle.length);
}

export function redactText(text, list) {
  let s = String(text);
  let count = 0;
  for (const { name, needle } of list) {
    if (!s.includes(needle)) continue;
    const parts = s.split(needle);
    count += parts.length - 1;
    s = parts.join(mark(name));
  }
  return { text: s, count };
}

export function redactor(list) {
  const hold = Math.max(0, ...list.map((n) => n.needle.length)) - 1;
  let carry = '';
  let count = 0;
  return {
    push(chunk) {
      const r = redactText(carry + chunk, list);
      count += r.count;
      if (r.text.length <= hold) { carry = r.text; return ''; }
      carry = r.text.slice(r.text.length - hold);
      return r.text.slice(0, r.text.length - hold);
    },
    end() { const r = redactText(carry, list); count += r.count; carry = ''; return r.text; },
    get count() { return count; },
  };
}
