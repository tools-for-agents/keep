# AGENTS.md — keep

🔐 **Use a secret without holding it.** Values are injected into the command you run and redacted from
what comes back. CLI + MCP. Part of [tools-for-agents](https://github.com/tools-for-agents).

## Setup

```bash
node --version            # 22+. Nothing to install.
npm test                  # = node --test; uses KEEP_BACKEND=file in a temp KEEP_HOME, never your keychain
node scripts/mutants.mjs  # every safety property, broken on purpose; the suite must go red for each
npm run mcp               # the MCP server, stdio
```

**Zero runtime dependencies, and that is a hard rule.**

## The rules this repo is built on

1. **No interface ever returns a value.** Not the CLI, not MCP, not an error message, not the audit log.
   If you add a tool, the MCP test fails when its name looks like get/read/reveal/export, and it greps
   the whole JSON-RPC conversation for every test value.
2. **Redaction is the product.** Any change to `src/redact.js` must keep the split-at-every-position
   stream test and the all-alignments base64 test green. If you find a new shape a value leaks in, add
   the needle *and* a canary.
3. **Tests never touch the real keychain or `~/.keep`.** Always set `KEEP_HOME` and `KEEP_BACKEND=file`.
4. **Say the limits out loud.** keep protects against accidental exposure and narrows misuse; it is not a
   boundary against a hostile process running as the same user. The README says so. Keep it that way.
