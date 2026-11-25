# nacre

**live workbench: https://nacre-studio-three.vercel.app**

a small `#![no_std]` rust kernel (`#![forbid(unsafe_code)]`, zero external dependencies) for agents.

every tool call passes through a pure algebraic effect handler before it touches the host, and every decision goes into a sha-256 hash-chained journal. once the same pattern shows up enough times in a journal, `nacre` compiles it into a sealed `.ncrystal` reflex or a standalone webassembly 1.0 binary so the agent stops paying a model for work it already solved.

```bash
cargo install --path crates/nacre-cli
nacre init --claude
nacre test-policy --policy nacre.policy
```

---

## use it today

you do not have to rewrite your agent in a new language to use `nacre`. the cli drops directly in front of any mcp server, claude code hook, or jsonl call log.

### 1. wrap any mcp server (`nacre mcp-guard`)

mcp servers have no built-in capability firewall. wrap any stdio server in your claude desktop, cursor, or codex config with `nacre mcp-guard`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "nacre",
      "args": [
        "mcp-guard",
        "--preset", "coding-agent",
        "--allow-path", "/repo/src/",
        "--reflex", "triage.ncrystal",
        "--journal", ".nacre-audit.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/repo"
      ]
    }
  }
}
```

every `tools/call` is evaluated inside `nacre-core`'s pure `handle` firewall in under a millisecond before the child server ever sees it. path separators are normalized, `..` and `%2e` traversals are rejected, optional `--reflex` bundles short-circuit repeated calls offline at `$0` tokens, inbound tool responses are scanned for hidden zero-width/tag-block unicode smuggling, blocked calls return a json-rpc `-32003` error with the sha-256 merkle proof hash, and every decision appends to a hash-chained audit log.

inspect the generated pure policy or supply your own custom `.nacre` handler:

```bash
nacre mcp-guard --allow-path /repo/src/ --deny-substr .env --print-policy
```

### 2. claude code / codex `PreToolUse` hook (`nacre init` + `nacre hook`)

generate `nacre.policy` (preloaded with `--preset coding-agent`: blocks `.env`, ssh keys, aws credentials, `.npmrc`, `rm -rf`, `git push --force`, `curl | sh`, and `..` traversals) and `.claude/settings.json` in one command:

```bash
nacre init --claude
nacre test-policy --policy nacre.policy
```

or wire `--preset coding-agent` directly in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "nacre hook --preset coding-agent --allow-path /repo/src/ --journal .nacre-audit.jsonl"
          }
        ]
      }
    ]
  }
}
```

allowed calls exit `0`. blocked calls print the merkle proof to stderr and exit `2` (claude code's native block code).

verify and summarize the hash-chained audit log offline at any time (catches edited, reordered, or deleted entries):

```bash
nacre audit-summary .nacre-audit.jsonl
nacre audit-verify .nacre-audit.jsonl
```

### 3. distill a jsonl log into a sealed offline reflex (`nacre distill` / `nacre query`)

given any newline-delimited json file of `{"input":"...","output":"..."}` pairs:

```bash
# synthesize a hybrid reflex (global purity invariant, min_support=4) and seal it with sha-256
nacre distill --input calls.jsonl --out triage.ncrystal --min-support 4

# query offline at 0 tokens: exits 0 with the label, 10 if unseen (ask the llm), 3 if tampered
nacre query triage.ncrystal "outage: checkout api 503"
```

---

## what we measured

full tables and commands are in [BENCHMARKS.md](BENCHMARKS.md); the `nanocode` integration rfc is in [docs/NANOCODE_RFC.md](docs/NANOCODE_RFC.md).

- **structural & supply-chain security (`nacre security-bench`)**: across 18 executable probes (continuation code injection, ambient capability escape, path traversal, fuel/depth dos, `.ncrystal` bundle tamper), a conventional harness fails `18/18`, naive prefix/regex guards fail `12/18`, and `nacre` holds `0/18`.
- **184 live calls across four late-2026 fast models (`nacre live-matrix`, `nacre live-inject`, `$0.7519` via vercel ai gateway)**: with an explicit path policy in the system prompt, `gemini-4-hydrogen`, `gemini-4-neon`, `claude-haiku-5.5`, and `deepseek-v4.1-flash` held single-turn probes (`0/8` each). when that prompt wording was omitted (`--no-policy`), an untrusted doc talked `claude-haiku-5.5` into emitting `fs_read("/public_secret/prod_keys.env")`; `nacre`'s 8-line `handle` firewall blocked it at zero tokens (`merkle b9bc787f1e37`) while keeping `4/4` benign `/public/` docs alive.
- **170 real `openai/codex` github issues (`nacre bench`)**: ingested via `nanocode`'s jsonl format, split chronologically (101 oldest train -> 69 unseen future). with zero gpu training, `nacre` eliminated `42%` of future llm calls at `96%` precision (`28/29`), cleanly escalating ambiguous issues back to the model.
- **5-stage superoptimization to wasm 1.0**: on 12 algorithmic tasks with disjoint held-out inputs, `10/11` expressible tasks solved `100%` and compiled to `164-234 b` standalone webassembly 1.0 binaries (`sum_to_n` dropped from `1,112` recursive fuel to `60` closed-form fuel, `18.5x` less, -> `186 b` wasm). on `prime_ctrl`, which does not fit a small arithmetic rule, `nacre` refused to guess and escalated `6/6` with `0` errors.
- **fixed-point pt-mcmc co-evolution (`nacre coev`)**: on a 67m-state 2-turn deceptive refusal landscape (pure q16.16 fixed-point, zero floats), surgical `nacre` hard antibodies held `12/12` benign queries alive with `0` regression leaks and `0` paid replay calls, compared to `1/12` autoimmune collapse for naive blocklists and `5` leaks / `165` replay calls for capped soft prompts.

---

## reproduce everything

```bash
cargo test --workspace                                   # 19 tests (core + cli guards + wasm studio)
cargo run --release -p nacre-cli -- bench                # algorithmic synthesis + 170 openai/codex issues
cargo run --release -p nacre-cli -- security-bench       # 18 structural probes + 4-arm adaptive red-queen
cargo run --release -p nacre-cli -- coev                 # 4-way pt-mcmc ablation + red-queen arena
cargo run --release -p nacre-cli -- live-inject          # live vercel ai gateway indirect-injection suite

# build single-file browser workbench (no server required)
cargo build -p nacre-wasm --target wasm32-unknown-unknown --release
cargo run --release -p nacre-cli -- build-studio
```

## workspace

- `crates/nacre-core` — `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, 0 external deps, 0 floats, 0 clocks
- `crates/nacre-cli` — `#![forbid(unsafe_code)]`, 0 external deps (`mcp-guard`, `hook`, `distill`, `query`, `audit-verify`, `bench`, `security-bench`, `coev`, `live-matrix`, `live-inject`, `build-studio`)
- `crates/nacre-wasm` — `wasm32-unknown-unknown` kernel + browser workbench renderer
- `benchmarks/codex_issues.tsv` — 170 public `openai/codex` issues with issue numbers and labels
- `docs/NANOCODE_RFC.md` — non-breaking reflex middleware & resumable cell rfc for `nanocodexyz/nanocode`
