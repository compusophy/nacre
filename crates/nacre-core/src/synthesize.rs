//! autonomous deterministic reflex synthesizer (zero floats, zero rng, zero llm required).
//!
//! reads recorded durable merkle traces, discovers minimal pure decision-tree or pattern
//! rules for delegating effectful heads, and passes every candidate through the mechanical
//! `crystallize_from_source` verification gate before acceptance.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::{sym, Arena, Node, SymId, TermId};
use crate::diag::{Diag, DiagCode};
use crate::distill::{crystallize_from_source, CrystalCert};
use crate::hash::Hash256;
use crate::journal::Trace;
use crate::lexicon::{Lexicon, Pattern};
use crate::syntax::{parse_term, print_term};

/// synthesis mode:
/// - `PureOffline`: distill a 100% pure reflex with 0 external capability calls.
/// - `HybridGuarded`: crystallize high-confidence pure branches (`support >= min_support`)
///   and fall back to `(perform <cap> ?x)` for rare/ambiguous/unseen inputs (gradual myelination).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynthMode {
    PureOffline,
    HybridGuarded { min_support: usize },
}

/// result of autonomous crystallization: verified lexicon, cryptographic certificate,
/// and the human/model-readable synthesized `nacre` rule source.
#[derive(Clone, Debug)]
pub struct AutoCrystal {
    pub lexicon: Lexicon,
    pub cert: CrystalCert,
    pub target_head: String,
    pub replaced_cap: String,
    pub synthesized_src: String,
    pub mode: SynthMode,
}

#[derive(Clone)]
struct Sample {
    input_term: TermId,
    input_str: Option<String>,
    reply_hash: Hash256,
    reply_sexpr: String,
}

/// automatically synthesize and mechanically verify a 100% pure offline reflex from recorded traces.
pub fn auto_crystallize(
    arena: &mut Arena,
    base_lexicon: &Lexicon,
    traces: &[Trace],
) -> Result<AutoCrystal, Diag> {
    auto_crystallize_with_mode(arena, base_lexicon, traces, SynthMode::PureOffline)
}

/// automatically synthesize and verify a reflex in either `PureOffline` or `HybridGuarded` mode.
pub fn auto_crystallize_with_mode(
    arena: &mut Arena,
    base_lexicon: &Lexicon,
    traces: &[Trace],
    mode: SynthMode,
) -> Result<AutoCrystal, Diag> {
    if traces.is_empty() {
        return Err(Diag::runtime(
            DiagCode::EmptyTraceSet,
            "auto_crystallize requires at least one trace",
        ));
    }

    // 1. find candidate delegating rules: `(rule (head ?x) (perform cap ?x))`
    let mut candidates: Vec<(SymId, SymId)> = Vec::new();
    for head in base_lexicon.heads() {
        if let Some(clauses) = base_lexicon.rules_for(head) {
            if clauses.len() == 1 && clauses[0].params.len() == 1 {
                if let Pattern::Var(param_v) = clauses[0].params[0] {
                    if let Node::App(bh, bargs) = arena.node(clauses[0].body) {
                        if *bh == sym::PERFORM && bargs.len() == 2 {
                            if let (Node::Sym(cap_sym), Node::Var(arg_v)) =
                                (arena.node(bargs[0]), arena.node(bargs[1]))
                            {
                                if *arg_v == param_v {
                                    candidates.push((head, *cap_sym));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        return Err(Diag::runtime(
            DiagCode::NoImprovement,
            "no single-capability delegating rule found to auto-crystallize",
        ));
    }

    // deterministic order by rule name
    candidates.sort_by(|a, b| arena.sym_name(a.0).cmp(arena.sym_name(b.0)));

    let mut last_err = Diag::runtime(
        DiagCode::NoImprovement,
        "no candidate rule could be crystallized from traces",
    );

    for (head, cap_sym) in candidates {
        let cap_name = String::from(arena.sym_name(cap_sym));
        let head_name = String::from(arena.sym_name(head));

        // 2. collect all observed (arg, reply) samples for `cap_sym` across traces
        let mut samples = Vec::new();
        let mut seen_input_reply: BTreeMap<Hash256, Hash256> = BTreeMap::new();
        let mut deterministic_mapping = true;

        for trace in traces {
            for ev in &trace.events {
                let eff_term = parse_term(arena, &ev.effect_sexpr)?;
                if let Node::App(eh, eargs) = arena.node(eff_term).clone() {
                    if eh == cap_sym && eargs.len() == 1 {
                        let arg = eargs[0];
                        let arg_hash = arena.hash(arg);
                        if let Some(&prev_reply) = seen_input_reply.get(&arg_hash) {
                            if prev_reply != ev.reply_hash {
                                deterministic_mapping = false;
                                break;
                            }
                            continue; // deduplicate identical sample
                        }
                        seen_input_reply.insert(arg_hash, ev.reply_hash);
                        let input_str = match arena.node(arg) {
                            Node::Bytes(bs) => core::str::from_utf8(bs).ok().map(String::from),
                            _ => None,
                        };
                        samples.push(Sample {
                            input_term: arg,
                            input_str,
                            reply_hash: ev.reply_hash,
                            reply_sexpr: ev.reply_sexpr.clone(),
                        });
                    }
                }
            }
            if !deterministic_mapping {
                break;
            }
        }

        if !deterministic_mapping || samples.is_empty() {
            continue;
        }

        // 3. synthesize a minimal rule source according to mode
        let synthesized_src = match mode {
            SynthMode::PureOffline => synthesize_rule_source(arena, &head_name, &samples),
            SynthMode::HybridGuarded { min_support } => {
                synthesize_hybrid_source(arena, &head_name, &cap_name, &samples, min_support.max(1))
            }
        };

        // 4. mechanically verify via the crystallization gate!
        match crystallize_from_source(arena, base_lexicon, traces, &synthesized_src) {
            Ok((lexicon, cert)) => {
                return Ok(AutoCrystal {
                    lexicon,
                    cert,
                    target_head: head_name,
                    replaced_cap: cap_name,
                    synthesized_src,
                    mode,
                });
            }
            Err(d) => {
                last_err = d;
            }
        }
    }

    Err(last_err)
}

fn synthesize_rule_source(arena: &Arena, head_name: &str, samples: &[Sample]) -> String {
    // case 1: constant output across all samples
    let first_hash = samples[0].reply_hash;
    if samples.iter().all(|s| s.reply_hash == first_hash) {
        return format!(
            "(rule ({} _) {})",
            head_name,
            protect_reply_sexpr(arena, &samples[0].reply_sexpr)
        );
    }

    // case 2: all inputs are utf-8 strings -> synthesize minimal discriminative token decision tree
    if samples.iter().all(|s| s.input_str.is_some()) {
        let indices: Vec<usize> = (0..samples.len()).collect();
        let tokens = extract_candidate_tokens(samples);
        let body = build_string_tree(arena, samples, &indices, &tokens, 0);
        return format!("(rule ({} ?x) {})", head_name, body);
    }

    // case 3: structured terms / ints / symbols -> linear constructor pattern clauses
    let mut out = String::new();
    // deterministic order by input hash
    let mut ordered: Vec<&Sample> = samples.iter().collect();
    ordered.sort_by_key(|s| arena.hash(s.input_term));
    for (i, s) in ordered.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "(rule ({} {}) {})",
            head_name,
            print_term(arena, s.input_term),
            protect_reply_sexpr(arena, &s.reply_sexpr)
        ));
    }
    out
}

/// hybrid guarded reflex synthesis (gradual myelination):
/// extracts pure, high-support discriminative guards (`count >= min_support` with 100% purity)
/// and delegates remaining/unseen/ambiguous inputs back to `(perform <cap> ?x)`.
fn synthesize_hybrid_source(
    arena: &Arena,
    head_name: &str,
    cap_name: &str,
    samples: &[Sample],
    min_support: usize,
) -> String {
    let fallback = format!("(perform {} ?x)", cap_name);
    if !samples.iter().all(|s| s.input_str.is_some()) {
        // exact clauses for observed terms + fallback to original capability for unseen terms
        let mut out = synthesize_rule_source(arena, head_name, samples);
        out.push_str(&format!("\n(rule ({} ?x) {})", head_name, fallback));
        return out;
    }

    let tokens = extract_candidate_tokens(samples);
    let mut remaining: Vec<usize> = (0..samples.len()).collect();
    let mut guards: Vec<(String, String)> = Vec::new();

    // greedily peel high-confidence token guards that satisfy the GLOBAL purity invariant:
    // a token guard is only admitted if it is 100% pure across the ENTIRE training journal
    // (never just pure on a shrunken residual slice!) and has len >= 4 to prevent 2-3 char
    // substring collisions ("in", "or", "to", "ui").
    for _ in 0..MAX_TREE_DEPTH {
        if remaining.len() < min_support {
            break;
        }
        let mut best: Option<(&str, usize, String, Vec<usize>)> = None;
        for tok in &tokens {
            if tok.len() < 4 {
                continue;
            }
            // global purity check over ALL samples in the journal (prevents greedy peeling leakage!)
            let mut global_matched = Vec::new();
            for (idx, s) in samples.iter().enumerate() {
                if s.input_str.as_deref().unwrap_or("").contains(tok.as_str()) {
                    global_matched.push(idx);
                }
            }
            if global_matched.len() < min_support || !is_pure(samples, &global_matched) {
                continue;
            }

            let mut matched = Vec::new();
            let mut rest = Vec::new();
            for &idx in &remaining {
                let txt = samples[idx].input_str.as_deref().unwrap_or("");
                if txt.contains(tok.as_str()) {
                    matched.push(idx);
                } else {
                    rest.push(idx);
                }
            }
            if matched.len() >= min_support && is_pure(samples, &matched) {
                let label = protect_reply_sexpr(arena, &samples[matched[0]].reply_sexpr);
                let better = match &best {
                    None => true,
                    Some((_, best_cov, _, _)) => matched.len() > *best_cov,
                };
                if better {
                    best = Some((tok.as_str(), matched.len(), label, rest));
                }
            }
        }
        if let Some((tok, _, label, rest)) = best {
            guards.push((String::from(tok), label));
            remaining = rest;
        } else {
            break;
        }
    }

    let mut body = fallback;
    for (tok, label) in guards.into_iter().rev() {
        body = format!("(if (str_contains ?x {}) {} {})", escape_str_lit(&tok), label, body);
    }
    format!("(rule ({} ?x) {})", head_name, body)
}

/// wrap compound replies in `(quote ...)` if needed so data constructors or symbols return cleanly.
fn protect_reply_sexpr(_arena: &Arena, sexpr: &str) -> String {
    // symbols, ints, strings, and inert data constructors evaluate to themselves in nacre,
    // except reserved builtin heads; keep clean readable syntax for normal labels & constructors.
    String::from(sexpr)
}

/// extract deterministic, deduplicated word/substring tokens from string samples.
fn extract_candidate_tokens(samples: &[Sample]) -> Vec<String> {
    let mut tok_set: BTreeSet<String> = BTreeSet::new();
    for s in samples {
        if let Some(txt) = &s.input_str {
            // split into contiguous word tokens (alphanumeric + '_' + '-')
            let bytes = txt.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if is_tok_byte(bytes[i]) {
                    let start = i;
                    while i < bytes.len() && is_tok_byte(bytes[i]) {
                        i += 1;
                    }
                    if i - start >= 2 {
                        tok_set.insert(String::from(&txt[start..i]));
                    }
                } else {
                    i += 1;
                }
            }
        }
    }
    // sort deterministically: shorter tokens first (prefer concise general features), then lexicographically
    let mut tokens: Vec<String> = tok_set.into_iter().collect();
    tokens.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    tokens
}

fn is_tok_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'/'
}

const MAX_TREE_DEPTH: usize = 12;

/// deterministic pure-integer decision tree builder (zero floats).
/// uses exact scaled-integer gini purity score: `sum(c_l^2) * n_r + sum(c_r^2) * n_l`
/// compared cross-multiplied by `n_l * n_r` in `u128`.
fn build_string_tree(
    arena: &Arena,
    samples: &[Sample],
    indices: &[usize],
    tokens: &[String],
    depth: usize,
) -> String {
    // base case: pure leaf
    let first_hash = samples[indices[0]].reply_hash;
    if indices.iter().all(|&i| samples[i].reply_hash == first_hash) {
        return protect_reply_sexpr(arena, &samples[indices[0]].reply_sexpr);
    }

    if depth < MAX_TREE_DEPTH {
        let mut best_tok: Option<(&str, Vec<usize>, Vec<usize>)> = None;
        // score represented as exact rational `num / den` compared via cross-multiplication in u128
        let mut best_pure_bonus: u8 = 0;
        let mut best_num: u128 = 0;
        let mut best_den: u128 = 1;

        for tok in tokens {
            let mut yes = Vec::new();
            let mut no = Vec::new();
            for &idx in indices {
                let txt = samples[idx].input_str.as_deref().unwrap_or("");
                if txt.contains(tok.as_str()) {
                    yes.push(idx);
                } else {
                    no.push(idx);
                }
            }
            if yes.is_empty() || no.is_empty() {
                continue;
            }

            let yes_pure = is_pure(samples, &yes);
            let no_pure = is_pure(samples, &no);
            let pure_bonus = (yes_pure as u8) + (no_pure as u8);

            // weighted purity = (sum(c_y^2)/|Y|) + (sum(c_n^2)/|N|)
            // = (sum(c_y^2)*|N| + sum(c_n^2)*|Y|) / (|Y| * |N|)
            let sy = sum_sq_counts(samples, &yes);
            let sn = sum_sq_counts(samples, &no);
            let ny = yes.len() as u128;
            let nn = no.len() as u128;
            let num = sy * nn + sn * ny;
            let den = ny * nn;

            let is_better = match best_tok {
                None => true,
                Some(_) => {
                    if pure_bonus != best_pure_bonus {
                        pure_bonus > best_pure_bonus
                    } else {
                        // num/den > best_num/best_den  <=>  num * best_den > best_num * den
                        num.saturating_mul(best_den) > best_num.saturating_mul(den)
                    }
                }
            };

            if is_better {
                best_pure_bonus = pure_bonus;
                best_num = num;
                best_den = den;
                best_tok = Some((tok.as_str(), yes, no));
            }
        }

        if let Some((tok, yes, no)) = best_tok {
            let yes_expr = build_string_tree(arena, samples, &yes, tokens, depth + 1);
            let no_expr = build_string_tree(arena, samples, &no, tokens, depth + 1);
            return format!(
                "(if (str_contains ?x {}) {} {})",
                escape_str_lit(tok),
                yes_expr,
                no_expr
            );
        }
    }

    // fallback: exact string match chain (guarantees 100% accuracy on any finite consistent sample set)
    let mut expr = protect_reply_sexpr(arena, &samples[indices[indices.len() - 1]].reply_sexpr);
    for &idx in indices[..indices.len() - 1].iter().rev() {
        let s = samples[idx].input_str.as_deref().unwrap_or("");
        let r = protect_reply_sexpr(arena, &samples[idx].reply_sexpr);
        expr = format!("(if (eq ?x {}) {} {})", escape_str_lit(s), r, expr);
    }
    expr
}

fn is_pure(samples: &[Sample], indices: &[usize]) -> bool {
    if indices.is_empty() {
        return true;
    }
    let h = samples[indices[0]].reply_hash;
    indices.iter().all(|&i| samples[i].reply_hash == h)
}

fn sum_sq_counts(samples: &[Sample], indices: &[usize]) -> u128 {
    let mut counts: BTreeMap<Hash256, u128> = BTreeMap::new();
    for &i in indices {
        *counts.entry(samples[i].reply_hash).or_insert(0) += 1;
    }
    counts.values().map(|&c| c * c).sum()
}

fn escape_str_lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
