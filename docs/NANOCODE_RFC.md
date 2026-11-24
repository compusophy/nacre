# rfc: journal-backed verified reflexes & resumable zero-unsafe cells for `nanocode`

> **non-breaking proposal** for `nanocodexyz/nanocode`: turn `nanocode-code-mode-engine`'s existing durable JSONL/SQLite journals from cold crash-recovery logs into **mechanically verified, zero-token reflexes**, and offer an optional `#![no_std]` / `#![forbid(unsafe_code)]` WASM cell target requiring zero `wasi-sdk` / C toolchain.

---

## 1. the two concrete opportunities observed in `nanocode`

after inspecting `crates/runtime/code-mode-engine/` (`journal.rs`, `cell.rs`, `Cargo.toml`) and `crates/README.md`:

1. **journals are currently write-only cold storage**
   - `nanocode-code-mode-engine` already records every tool/model invocation as structured `JournalEntry::Call { id, name, input, host }` + `JournalEntry::Result { id, encoded, success }` pairs.
   - when an agent repeatedly invokes an expensive classification/routing/parsing tool across sessions, it pays full frontier-LLM latency and token cost every time, even though the durable journal already holds the exact ground-truth `(input, output)` trajectories needed to distill and verify deterministic shortcuts.

2. **local WASM cells currently require `djs-embed` (QuickJS/C) + `wasi-sdk` + 6 JS non-determinism shims**
   - `crates/README.md` notes that `wasm32` with `local-cells` must be built against `wasi-sdk` because QuickJS is C, ships a build-time heap snapshot (`code-mode.snap`), and must journal `Clock`, `Monotonic`, `Random`, `Bytes`, `Timeout`, and `Timer` entries (up to `JOURNAL_LIMIT_BYTES = 32 MB`) to replay JS scripts from line 1 on crash.

---

## 2. proposed non-breaking integration: opt-in reflex middleware (`nacre-core`)

`nacre-core` is a standalone, zero-dependency, `#![no_std]`, `#![forbid(unsafe_code)]` Rust crate (`75.7 KB` gzipped on `wasm32-unknown-unknown`, zero C toolchain) that natively speaks `nanocode-code-mode-engine`'s `JournalEntry` JSONL wire format (`nacre_core::nanocode_bridge`):

```text
nanocode JournalEntry JSONL (Call + Result pairs)
        │
        ▼  nacre_core::nanocode_bridge::crystallize_from_nanocode_jsonl()
┌──────────────────────────────────────────────────────────┐
│ 1. strip JS nondet entries (clock/random/monotonic)      │
│ 2. synthesize pure or hybrid-guarded symbolic reflex     │
│ 3. mechanically verify 100% replay parity over journal   │
│    + static capability non-escalation (caps_after ⊆ base)│
│ 4. optional tier-2 wasm 1.0 emit (~164-234 B per rule)   │
│ 5. seal portable sha-256 `.ncrystal` bundle              │
└──────────────────────────────────────────────────────────┘
        │
        ▼  opt-in middleware before model/tool dispatch
  known pattern  ──► 0 LLM tokens, <0.1 ms, offline verified
  novel/ambiguous ──► yields `(perform tool ?x)` -> normal nanocode LLM turn
```

---

## 3. measured systems & empirical comparison

| axis | `nanocode-code-mode-engine` (QuickJS) | `nacre-core` (algebraic cell + reflex kernel) |
| :--- | :--- | :--- |
| language & safety | Rust wrapper (2,394 LOC) + C QuickJS (`djs-embed`) | 100% pure Rust `#![no_std]`, `#![forbid(unsafe_code)]`, 0 external deps |
| `wasm32` build requirement | requires `wasi-sdk` C cross-compiler for `local-cells` | plain `cargo build --target wasm32-unknown-unknown` (`75.7 KB` gzip) |
| determinism shims in journal | 6 extra entry kinds (`clock`, `monotonic`, `random`, `bytes`, `timeout`, `timer`) | **0** (no clocks, no RNG, no floats, no `HashMap` in core) |
| crash/resume mechanism | replay JS script from line 1 against up to `32 MB` journal + `code-mode.snap` | plug reply into `<250 B` content-addressed residual `(cont ...)` |
| prompt-injection boundary | JS runtime eval surface | structural auto-quoting (`protect_value`) + static transitive cap proofs |
| real-world `openai/codex` issue triage (170 live issues, 101 train → 69 unseen future) | 100% LLM calls | **`hybrid (support=4)`: 96% offline precision (`28/29`), 42% future LLM calls eliminated** (`50%` eliminated at `91%` precision with `support=2`) |
| algorithmic synthesis + Tier-2 WASM (`sum_to_n`) | n/a | climbs `gen0 oracle → gen2 recursive → gen3 O(1) closed form (18.5× fuel cut) → 186 B native wasm` |

---

## 4. minimal reproduction

```bash
git clone <nacre-repo>
cd nacre
cargo test --workspace
cargo run --release -p nacre-cli -- bench

# ingest any real nanocode cell journal JSONL file directly:
cargo run --release -p nacre-cli -- ingest-nanocode path/to/journal.jsonl llm_classify 4 skill.ncrystal
cargo run --release -p nacre-cli -- verify skill.ncrystal
```

the goal is **not** to replace QuickJS for arbitrary frontier-model scripting—it is to give `nanocode` an opt-in, zero-dependency, cryptographically verifiable **reflex compilation layer** directly over the journals `nanocode` already records.
