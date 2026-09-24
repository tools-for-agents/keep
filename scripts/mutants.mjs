// CAN THE TEST SUITE STILL FAIL?
//
// Every other gate here asks "is the code right". This one asks the question underneath it:
// IS ANYTHING STILL WATCHING. A suite that has quietly stopped covering a property goes green
// for exactly the same reason as a suite that is passing honestly, and there is no way to tell
// the two apart by looking at the green.
//
// It has happened across this kit more than once. anvil's Docker tests were SKIPPED for months
// — 11 pass, 0 fail, 9 skipped, green every run — while the tool was completely broken on
// Linux. lens's file walk swallowed .env files, and twenty green tests never saw it.
//
// So: break the code ON PURPOSE, in the exact places whose breakage would cost the most, and
// demand the suite goes RED. If it stays green, the canary is dead and this job fails — the
// test guarding that line has stopped guarding it, and you find out today rather than the
// morning after it mattered.
//
//   node scripts/mutants.mjs
//
// Each canary must have EXACTLY ONE anchor. An anchor that has drifted is a canary that
// silently stopped watching, so a missing or ambiguous anchor is a hard failure, never a skip.

import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const CANARIES = [
  {
    why: 'base64 is searched at ALL THREE byte alignments — at one, a Basic auth header ("user:" + secret) walks the secret straight out',
    file: 'src/redact.js',
    find: '  for (let k = 0; k < 3; k++) {',
    into: '  for (let k = 0; k < 1; k++) {',
  },
  {
    why: 'the stream holds back a tail at every chunk boundary — without it a secret split across two chunks is printed in two halves',
    file: 'src/redact.js',
    find: '  const hold = Math.max(0, ...list.map((n) => n.needle.length)) - 1;',
    into: '  const hold = 0;',
  },
  {
    why: 'EVERY kept value is redacted, not only the injected ones — a secret the command found on its own is still a secret',
    file: 'src/run.js',
    find: '  const list = needles(all);',
    into: '  const list = needles(injected);',
  },
  {
    why: 'a restricted secret cannot be handed to a program outside its allow-list (sh -c, node -e, curl)',
    file: 'src/run.js',
    find: "    if (!allow.includes('*') && !allow.includes(cmd)) {",
    into: '    if (false) {',
  },
  {
    why: 'a restricted secret is run by NAME, not by path — ./gh is whatever file sits in the working directory',
    file: 'src/run.js',
    find: "    if (!allow.includes('*') && String(argv[0]).includes('/')) {",
    into: '    if (false) {',
  },
  {
    why: 'the command recorded in the result and the audit log is redacted — an agent that typed a raw value must not have it logged',
    file: 'src/run.js',
    find: "        command: redactText(argv.join(' '), list).text,",
    into: "        command: argv.join(' '),",
  },
  {
    why: 'vault files are written 0600 — readable by nobody but you',
    file: 'src/vault.js',
    find: '  fs.writeFileSync(tmp, text, { mode: 0o600 });',
    into: '  fs.writeFileSync(tmp, text, { mode: 0o644 });',
  },
  {
    why: 'values are refused below the redactable length — a 3-character "secret" would erase ordinary text everywhere',
    file: 'src/vault.js',
    find: '  if (v.length < MIN_LEN) throw',
    into: '  if (false) throw',
  },
];

// spawnSync returns status:null when IT kills the child for exceeding the timeout — a TIMEOUT,
// not a test failure. Reading that as "the suite is already red" turns a slow suite into a broken
// one. Distinguish them: a suite that never finished has not answered, and a mutant that makes the
// suite hang has not been "killed". (Only iris is slow enough to hit this, but the bug was latent
// in every copy of this helper.)
const TIMEOUT_MS = 600_000;
const run = () => {
  const r = spawnSync('npm', ['test'], { encoding: 'utf8', timeout: TIMEOUT_MS });
  // A SKIPPED test cannot kill a canary — it did not run. So the skip count is not trivia here:
  // it is the difference between "nothing guards this line" and "the guard never got to look".
  const skipped = +(`${r.stdout || ''}${r.stderr || ''}`.match(/^\s*(?:ℹ|#)\s*skipped\s+(\d+)/m)?.[1] || 0);
  return { failed: r.status !== 0, timedOut: r.signal === 'SIGTERM' || r.error?.code === 'ETIMEDOUT', skipped };
};

// 🔑 AND IT MUST NOT RUN TWICE AT ONCE. This tool EDITS YOUR SOURCE IN PLACE, so two concurrent runs
// do not merely confuse each other — they can make a planted bug PERMANENT:
//
//     run B plants a mutation in core.js
//     run A reads core.js as its "original"      ← the original now CONTAINS B's bug
//     run B restores its own copy
//     run A restores ITS "original"              ← re-plants B's bug, and A believes it cleaned up
//
// The sabotage is now in your tree, no process is left to undo it, and the tool that put it there
// reports success. It is not theoretical: two overlapping runs turned this repo's suite red, and the
// only message was "THE SUITE IS ALREADY RED" — which names neither the file nor the line.
// An exclusive lock, taken BEFORE the baseline (a concurrent run poisons the baseline too).
const LOCK = new URL('../.mutants.lock', import.meta.url);
try {
  writeFileSync(LOCK, String(process.pid), { flag: 'wx' });   // wx = fail if it already exists
} catch {
  let holder = '?';
  try { holder = readFileSync(LOCK, 'utf8').trim(); } catch { /* raced with a clean exit */ }
  const alive = holder !== '?' && (() => { try { process.kill(+holder, 0); return true; } catch { return false; } })();
  if (alive) {
    console.error(`another mutants run (pid ${holder}) is already editing this source tree. `
      + 'Two at once can make a planted bug PERMANENT — see the note above. Wait for it, or kill it.');
    process.exit(1);
  }
  // The holder is gone (killed before it could clean up). Its restore-on-exit ran, so the tree is
  // sound; the lock is just litter. Take it.
  writeFileSync(LOCK, String(process.pid));
}
const dropLock = () => { try { unlinkSync(LOCK); } catch {} };
process.on('exit', dropLock);

// The baseline must be GREEN, or every canary "dies" for free and this job proves nothing.
console.log('baseline…');
const base = run();
if (base.timedOut) {
  console.error(`THE SUITE DID NOT FINISH within ${TIMEOUT_MS / 1000}s — a timeout, not a failure. `
    + 'Raise TIMEOUT_MS or speed up the suite; do not read a slow suite as a broken one.');
  process.exit(1);
}
if (base.failed) { console.error('THE SUITE IS ALREADY RED. Nothing can be proven from here.'); process.exit(1); }
// 🔑 A canary cannot be killed by a test that DID NOT RUN. If the baseline skipped tests, then any
// canary those tests guard will "survive" — and it will look exactly like a coverage hole, sending
// you to write a test that already exists instead of to the one-line fix (start Docker / install
// Chrome). Two different facts, two different fixes; they must not print the same sentence.
// This is anvil's cycle-13 lesson one layer up: in CI a skipped test is a FAILED test, so CI never
// sees this — it is the LOCAL run that lies, and the local run is where you do the work.
if (base.skipped) {
  console.log(`⚠ the baseline SKIPPED ${base.skipped} test(s) — those cannot kill a canary, because they `
    + 'do not run. A survivor below is far more likely to be a missing dependency than a missing test.');
}
console.log('baseline: green\n');

// 🔑 THE MUTATION IS WRITTEN INTO YOUR SOURCE FILE and undone once the suite has run. If this
// process dies in between — Ctrl-C, SIGTERM, a cancelled CI job, an OOM kill — the planted bug is
// LEFT IN YOUR TREE: a deliberately subtle one-character sabotage, sitting exactly where your real
// fix was, ready for the next `git add -A`. It is not hypothetical — a killed run left
// `raw && !isHtml` in scout's core.js, silently reverting a real fix, and the next mutants run said
// only "THE SUITE IS ALREADY RED", which names neither the file nor the line.
//
// A TOOL THAT PLANTS BUGS ON PURPOSE MUST BE THE ONE THING THAT ALWAYS CLEANS UP AFTER ITSELF.
// writeFileSync is synchronous, so it is safe in an exit handler.
let planted = null;                       // { file, orig } while a mutation is on disk
const restore = () => { if (planted) { writeFileSync(planted.file, planted.orig); planted = null; } };
process.on('exit', restore);
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'])
  process.on(sig, () => { restore(); process.exit(130); });
process.on('uncaughtException', (e) => { restore(); console.error(e); process.exit(1); });

let dead = 0;
for (const c of CANARIES) {
  const orig = readFileSync(c.file, 'utf8');
  const hits = orig.split(c.find).length - 1;
  if (hits !== 1) {
    console.error(`✗ ANCHOR DRIFTED in ${c.file}: found ${hits}×\n    ${c.find}\n  ` +
      'A canary whose anchor has moved is not watching anything. Re-point it.');
    dead++; continue;
  }
  planted = { file: c.file, orig };
  writeFileSync(c.file, orig.replace(c.find, c.into));
  const res = run();
  restore();

  // A timeout on a mutant is NOT a kill: a broken mutant can hang instead of failing fast.
  if (res.timedOut) {
    console.error(`✗ INCONCLUSIVE — the suite timed out with this broken, so we cannot say it was killed:\n    ${c.why}`);
    dead++;
  } else if (!res.failed) {
    console.error(`✗ SURVIVED — the suite went GREEN with this broken:\n    ${c.why}\n    ${c.file}`);
    console.error(res.skipped
      ? `  …but ${res.skipped} test(s) were SKIPPED. A test that did not run cannot kill a canary, so this\n`
        + '  is most likely a MISSING DEPENDENCY (docker down? no chrome?), not a missing test.\n'
        + '  Provide it and re-run — do not go writing a test that may already exist.'
      : '  Nothing is guarding that line any more.');
    dead++;
  } else {
    console.log(`✓ killed — ${c.why}`);
  }
}

if (dead) { console.error(`\n${dead} canary/canaries are not watching. The suite cannot prove what it claims.`); process.exit(1); }
console.log(`\nall ${CANARIES.length} canaries killed — the suite can still fail where it matters.`);
