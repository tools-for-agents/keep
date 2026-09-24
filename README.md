# 🔐 keep

**Use a secret without holding it.** An encrypted vault whose values are *injected* into the commands an agent runs, and *redacted* from everything that comes back. The agent works with `‹keep:GH_TOKEN›`. The token itself never enters its context, its transcript, or anything that reads the transcript later.

Part of [tools-for-agents](https://github.com/tools-for-agents). **Zero dependencies**: the Node standard library plus your OS keychain. CLI + MCP.

---

## Why this exists

An agent that needs an API key today has one way to get it: read it. It runs `cat .env` or `echo $TOKEN`, or it asks you to paste the key into the chat. From that moment the value sits in the model's context. It also sits in the session transcript on disk (`~/.claude/projects/*.jsonl`), and every process that reads transcripts can see it: summarisers, search indexes, memory systems that dream sessions into long-term memory.

Measured on the machine this was built on, on the day it was built: the first `keep scan --transcripts` went through **7,335 transcript files (1.28 GB) in ten seconds** and found a **Firebase service-account private key**. An agent had read the key out of a project's `.env` weeks earlier, and it had been in a transcript ever since.

keep closes that path. The agent names the secret, and keep hands the value to the *program*, never to the agent:

```bash
keep run --with GH_TOKEN -- gh api user
keep run -- curl -H 'Authorization: Bearer {{OPENAI_API_KEY}}' https://api.openai.com/v1/models
```

Anything the program prints goes through a redactor built from **every** kept value, and the agent reads `‹keep:OPENAI_API_KEY›` wherever the value would have appeared.

## Install

```bash
git clone https://github.com/tools-for-agents/keep.git && cd keep
node src/cli.js init                      # creates ~/.keep; the master key goes into the OS keychain
ln -s "$PWD/src/cli.js" ~/.local/bin/keep
claude mcp add keep --scope user -- node "$PWD/mcp/mcp-server.js"
```

Node 22+. Nothing to `npm install`.

## For the person

```bash
keep set GH_TOKEN                     # typed hidden, never echoed, never in shell history
pbpaste | keep set OPENAI_API_KEY     # or piped
keep set DEPLOY_KEY --allow gh,fly    # only these programs may receive it
keep import .env                      # keep every KEY=value in a dotenv file (then delete the file)
keep list                             # names, policy, usage — and what agents have asked for
keep audit                            # every use: when, which names, which command, exit code
keep scan --transcripts               # has anything already leaked?
keep redact --patterns < in > out     # a filter: kept values and known key shapes → their names
```

`keep redact` is for the *other* tools that store what an agent wrote: a memory that dreams transcripts, a log shipper, a search index. [ghost](https://github.com/tools-for-agents/ghost) pipes every session through it before dreaming, so a key an agent once printed does not end up in long-term memory. With `--patterns` it also masks anything shaped like a well-known key, and it masks a private key as a whole block, body included, not just its `BEGIN` line.

## guard: an agent does not read a secret file

keep lets an agent use a secret without holding it, but nothing stopped an agent from holding one
anyway. The leak keep's first scan found was exactly that: an agent looking for a database URL ran
`grep -n "…\|PG\|…" backend/.env`, the base64 body of a Firebase private key happened to contain
"PG", and the key went into the transcript. There was no intent and no attack, just a grep.

```bash
keep guard --install      # a Claude Code PreToolUse hook (Bash|Read); keeps every other hook; backs settings up
keep guard --uninstall
```

A command that **prints** a secret file (`cat`, `grep`, `head`, `sed`, `awk`, `git diff`, `base64 <`,
`curl -d @.env`, and so on) or a `Read` of one (`.env*`, `*.pem`, `*.key`, `id_rsa`,
`*service-account*.json`, `credentials.json`, `.netrc`, `.npmrc`, …) is refused. The refusal
carries the way forward, which an agent can take on its own with no human awake:
`keep import <file>` stores every value without printing one, and `keep run --with NAME -- …` uses
it. Nothing that doesn't print a secret is touched: templates (`.env.example`), `cp .env.example .env`,
`source .env && npm start`, writing to a secret file, `ls`, `mv`, and keep's own commands.

## For the agent (MCP)

| Tool | What it does |
|---|---|
| `keep_list` | names, allowed commands and usage for each kept secret, never values; also the secrets you asked for that have not arrived yet |
| `keep_run` | runs argv with the named secrets injected as env vars; `{{NAME}}` in an argument is replaced; stdout and stderr come back redacted |
| `keep_scan` | reports where a kept value, or anything shaped like a well-known key, shows up in files or transcripts: file, line and name, never the value |
| `keep_request` | asks your person for a secret you lack; it shows up in their `keep list`, and is answered by `keep set` |
| `keep_audit` | the usage log |

**No tool returns a value.** That is the design, not a gap in it, and a test fails if a tool whose name looks like `get`, `read`, `reveal` or `export` ever appears.

## What the redactor catches

A secret leaks in more shapes than its own. `curl -v` prints the Authorization header, and a Basic header is `base64("user:" + secret)`: the secret's bytes, shifted by the username and written in another alphabet. So every value becomes a set of needles:

- the raw value, its JSON-escaped form and its URL-encoded form;
- **base64 and base64url at all three byte alignments.** base64 works in 3-byte groups, so how the secret encodes depends on how many bytes came before it. keep encodes it after 0, 1 and 2 bytes of padding and keeps only the characters that depend on the secret alone, which finds it inside *any* base64 string.

Output is streamed, and a value can be split across two chunks. The redactor holds back (longest needle − 1) characters at each boundary. A test splits a secret at every possible position and checks all of them.

## Policy

`keep set NAME --allow gh,curl` restricts a secret to named programs. A restricted secret:
- cannot be handed to `sh -c`, `node -e` or `python -c`, which is the move an agent would make if it had been talked into exfiltrating the value;
- must be run by name (`gh`) and not by path (`./gh`), because a file named `gh` in the working directory is not the `gh` you meant.

## Honest limits

keep is built against **accidental exposure** (a value in a context window, a transcript or a log) and it **narrows misuse**. It is **not a boundary against a hostile process running as you**, and it says so here rather than let you find out:

- Anything running as your user can ask the keychain for the master key, or read `~/.keep/master.key` on the file backend, just as it could read your `.env`.
- A program you allow can do whatever it likes with the value. `--allow curl` lets curl send the key to any host.
- Redaction catches the shapes listed above. It does not catch a value that was reversed, hashed, split or re-encoded some other way before it was printed.
- `keep status` says which backend holds the master key. On Linux without `secret-tool` it is a 0600 file next to the vault, which is weaker, and keep prints that when the vault is created.

## Files

| | |
|---|---|
| `~/.keep/secrets.enc` | the values: AES-256-GCM, one authenticated blob. If it has been altered it fails to open; it never decrypts to garbage |
| `~/.keep/index.json` | names, allow-lists, usage counts, requests. Never a value |
| `~/.keep/audit.jsonl` | one line per use, with the command already redacted |
| OS keychain · `tools-for-agents.keep` | the 32-byte master key (macOS `security`, Linux `secret-tool`, otherwise `~/.keep/master.key`) |

Every file is 0600 in a 0700 directory, and each write goes to a temp file first and is renamed into place, so a crash never leaves half a vault.

| Env | |
|---|---|
| `KEEP_HOME` | vault directory (default `~/.keep`); **always redirect it in tests** |
| `KEEP_BACKEND` | `keychain` · `secret-tool` · `file` |
| `KEEP_TRANSCRIPTS` | where `--transcripts` looks (default `~/.claude/projects`) |

## Test

```bash
node --test               # 29 tests; the file backend, no keychain touched
node scripts/mutants.mjs  # breaks each safety property on purpose and demands the suite goes red
```


## The agent toolkit

<!-- toolkit:start — generated from tools.json by tools-for-agents.github.io/build/toolkit-block.mjs; edit that, not this -->

`keep` is the **hold secrets** leg of **[tools-for-agents](https://tools-for-agents.github.io)** — an operating system for agents.
Nine zero-dependency, MCP-native tools that form one loop, with a self at its centre:

| | | |
|---|---|---|
| 🛰️ | [agent-hq](https://github.com/tools-for-agents/agent-hq) | coordinate — The company's work, made visible. |
| 🔎 | [lens](https://github.com/tools-for-agents/lens) | read code — Read code without reading files. |
| ⚒ | [anvil](https://github.com/tools-for-agents/anvil) | run safely — Run it before you claim it works. |
| 🔐 | **keep** | **hold secrets** — Use a secret without holding it. |
| 🧠 | [cortex](https://github.com/tools-for-agents/cortex) | remember — A second brain that outlives the context window. |
| 🧭 | [scout](https://github.com/tools-for-agents/scout) | read the web — The web, ~90% lighter. |
| 🔻 | [prism](https://github.com/tools-for-agents/prism) | read data — Read data without reading the blob. |
| ◎ | [recall](https://github.com/tools-for-agents/recall) | recall it all — One query. Every store you have. |
| 👁 | [iris](https://github.com/tools-for-agents/iris) | see — Look at what you built. |
| 👻 | [ghost](https://github.com/tools-for-agents/ghost) | *the self at the centre* — A self that persists across sessions. Not a tool: it is what the agent **is** while it calls these. |

**Reading this as an agent?** [`/llms.txt`](https://tools-for-agents.github.io/llms.txt) is the map, and
[`/tools.json`](https://tools-for-agents.github.io/tools.json) hands you all **79 MCP tools** — every name, every
description, every install command — in **one fetch**, without cloning anything.

<!-- toolkit:end -->

## License

MIT
