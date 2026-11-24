# nacre

> deterministic symbolic cells, durable merkle journals, verified reflexes, and co-evolutionary security — in pure `#![no_std]` rust with zero external dependencies.

**live studio**: https://nacre-studio-three.vercel.app

---

## what nacre does

1. **content-addressed merkle-dag cells (`nacre-core::arena`, `eval`)**
   - code, data, rules, effects, and suspended continuations live in one hash-consed sha-256 arena (`#![no_std]`, `#![forbid(unsafe_code)]`, 0 external deps, 0 floats, 0 clocks).
   - algebraic `perform`/`handle` unifies durability, capability firewalls, mocking, and fractal sub-cells into one small-step primitive. yielding an effect returns a tiny (`<250 B`), human-readable, injection-proof residual continuation `(cont ...)`.
2. **journal-backed reflex crystallization (`journal`, `distill`, `synthesize`, `evolve`, `wasm_emit`)**
   - the durable execution journal *is* the self-optimization oracle.
   - distills pure or hybrid-guarded reflexes from recorded traces (including `nanocode-code-mode-engine`'s exact `JournalEntry` JSONL wire format via `nanocode_bridge`), mechanically proves static capability non-escalation + 100% replay parity, compiles pure `i64` rules into standalone `164–234 B` WebAssembly 1.0 binaries with a built-in differential oracle, and seals portable `.ncrystal` bundles.
3. **co-evolutionary security arena (`pt_mcmc`, `coev`, `security_bench`, `live`)**
   - pure fixed-point Q16.16 parallel-tempered MCMC (replica exchange + genetic crossover + MAP-Elites) paired with `alive`-gated surgical `nacre` hard antibodies and a pure-rust live cross-model runner (`google/gemini-4-hydrogen` vs `google/gemini-4-neon`).

---

## headline verified benchmarks

full tables and Run 1 → Run 2 → Run 3 hill-climb log in [BENCHMARKS.md](BENCHMARKS.md); `nanocode` integration RFC in [docs/NANOCODE_RFC.md](docs/NANOCODE_RFC.md).

- **domain a (12 algorithmic synthesis tasks, disjoint held-out)**: `10/11` expressible solved `100%` on unseen held-out + compiled to `164–234 B` native WASM 1.0 (`0` held-out wrong across all 12 tasks including `prime_ctrl` falsification control); `sum_to_n` climbs 5 stages (`gen0 oracle → gen2 recursive → gen3 O(1) closed form`: **`18.5×` / `94.6%` fuel collapse** → `186 B` WASM).
- **domain c (170 real `openai/codex` github issues via `nanocode` JSONL bridge, chronological 101 train → 69 unseen future)**: **`96%` offline precision (`28/29`) while eliminating `42%` of future llm calls** (`50%` eliminated at `91%` precision).
- **domain d & e (security control matrix & pt-mcmc red-queen arena)**: **`18/18` breaches on naked control → `12/18` on naive guard → `0/18` on `nacre`**; on hardened gen 4 checkpoints, `pt_mcmc_genetic` (`37%` swap acceptance) beats `greedy`, `single_temp_sa`, and `random`; `nacre` hard antibodies hold `12/12` (`100%`) `alive` with `0` regression leaks and `0` paid replay LLM calls vs. `1/12` autoimmune collapse (naive blocklist) and `5` leaks / `165` replay calls (capped soft prompt).
- **domain f & g (184 live vercel ai gateway calls across `gemini-4-hydrogen`, `gemini-4-neon`, `claude-haiku-5.5`, `deepseek-v4.1-flash`, `$0.7519` total)**: `4/4` models breach turn 1 naked; `claude-haiku-5.5` hijacked live on `prefix_collision` (`fs_read("/public_secret/prod_keys.env")`) under default agent prompt and cryptographically blocked by `nacre` (`merkle b9bc787f1e37`, `0/8` breaches, `4/4` benign `alive_ok`); explicit single-turn policies hold `32/32` across all 4 models while exposing a **73× live cost spread** (`$0.0013` Haiku 5.5 vs. `$0.0956` Gemini 4 Neon per 12-call suite).

---

## quick start

```bash
# run all 14 core verification tests
cargo test --workspace

# run end-to-end kernel demo
cargo run -p nacre-cli -- demo

# run 3-domain hill-climb & real openai/codex benchmark
cargo run --release -p nacre-cli -- bench

# run 4-way pt-mcmc ablation & red-queen co-evolution arena
cargo run --release -p nacre-cli -- coev

# run naked-control vs naive-guard vs nacre security matrix
cargo run --release -p nacre-cli -- security-bench

# run live N x N cross-model tournament via vercel ai gateway (pure rust, 0 node/python)
cargo run --release -p nacre-cli -- live-matrix \
  --models google/gemini-4-hydrogen,google/gemini-4-neon,anthropic/claude-haiku-5.5,deepseek/deepseek-v4.1-flash-1017-ultrafast --turns 3

# run live indirect prompt-injection benchmark (conventional harness vs nacre handle firewall)
cargo run --release -p nacre-cli -- live-inject \
  --models google/gemini-4-hydrogen,google/gemini-4-neon,anthropic/claude-haiku-5.5,deepseek/deepseek-v4.1-flash-1017-ultrafast

# build single-file offline wasm studio
cargo build -p nacre-wasm --target wasm32-unknown-unknown --release
cargo run -p nacre-cli -- build-studio
```

## workspace layout

- `crates/nacre-core` — `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, 0 external deps
- `crates/nacre-cli` — `#![forbid(unsafe_code)]`, 0 external deps (`demo`, `run`, `caps`, `replay`, `crystallize`, `verify`, `ingest-nanocode`, `wasm-reflex`, `bench`, `coev`, `security-bench`, `live-matrix`, `live-inject`, `build-studio`)
- `crates/nacre-wasm` — `wasm32-unknown-unknown` kernel + pure-rust studio ui renderer
- `benchmarks/codex_issues.tsv` — 170 real public `openai/codex` issues with issue numbers & labels
- `docs/NANOCODE_RFC.md` — non-breaking reflex middleware & resumable cell RFC for `nanocodexyz/nanocode`
