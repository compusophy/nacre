//! journal-backed equivalence verifier & reflex crystallization gate.
//!
//! proves mechanically over recorded merkle journals that a proposed pure/faster rule set:
//!   1. never escalates static capabilities (`candidate_caps ⊆ base_caps`),
//!   2. reproduces bit-for-bit identical outputs across 100% of recorded traces offline, and
//!   3. strictly reduces external effects or fuel consumption.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::{Arena, TermId};
use crate::diag::{Diag, DiagCode};
use crate::eval::{eval, plug_hole, Outcome};
use crate::fuel::Fuel;
use crate::hash::{Hash256, Sha256, TAG_CERT};
use crate::journal::{Trace, TraceOutcome};
use crate::lexicon::{compile_rule, Lexicon};
use crate::syntax::{parse_term, parse_terms};

/// cryptographic proof certificate minted when a reflex passes the crystallization gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrystalCert {
    pub base_lexicon_hash: Hash256,
    pub new_lexicon_hash: Hash256,
    pub traces_merkle_root: Hash256,
    pub trace_count: u32,
    pub base_effects: u64,
    pub new_effects: u64,
    pub base_fuel: u64,
    pub new_fuel: u64,
    pub caps_before: Vec<String>,
    pub caps_after: Vec<String>,
    pub cert_hash: Hash256,
}

impl CrystalCert {
    pub fn effects_eliminated(&self) -> u64 {
        self.base_effects.saturating_sub(self.new_effects)
    }

    pub fn fuel_saved(&self) -> i64 {
        (self.base_fuel as i64) - (self.new_fuel as i64)
    }

    pub fn is_now_pure(&self) -> bool {
        self.caps_after.is_empty()
    }

    fn compute_hash(&self) -> Hash256 {
        let mut h = Sha256::new();
        h.update_u8(TAG_CERT);
        h.update_hash(&self.base_lexicon_hash);
        h.update_hash(&self.new_lexicon_hash);
        h.update_hash(&self.traces_merkle_root);
        h.update_u32(self.trace_count);
        h.update_u64(self.base_effects);
        h.update_u64(self.new_effects);
        h.update_u64(self.base_fuel);
        h.update_u64(self.new_fuel);
        h.update_u32(self.caps_before.len() as u32);
        for c in &self.caps_before {
            h.update_len_bytes(c.as_bytes());
        }
        h.update_u32(self.caps_after.len() as u32);
        for c in &self.caps_after {
            h.update_len_bytes(c.as_bytes());
        }
        h.finalize()
    }
}

/// verify a proposed reflex rule source against a batch of real recorded `traces`,
/// returning the promoted `Lexicon` and its cryptographic `CrystalCert`.
pub fn crystallize_from_source(
    arena: &mut Arena,
    base_lexicon: &Lexicon,
    traces: &[Trace],
    candidate_rules_src: &str,
) -> Result<(Lexicon, CrystalCert), Diag> {
    if traces.is_empty() {
        return Err(Diag::runtime(
            DiagCode::EmptyTraceSet,
            "crystallization requires at least one recorded trace",
        ));
    }

    let forms = parse_terms(arena, candidate_rules_src)?;
    if forms.is_empty() {
        return Err(Diag::runtime(
            DiagCode::InvalidRuleForm,
            "candidate reflex source contains no rules",
        ));
    }
    let mut candidate_rules = Vec::with_capacity(forms.len());
    for f in forms {
        candidate_rules.push(compile_rule(arena, f)?);
    }

    let base_lex_hash = base_lexicon.hash(arena);
    let new_lexicon = base_lexicon.with_replaced_rules(candidate_rules);
    let new_lex_hash = new_lexicon.hash(arena);

    let mut base_effects_total = 0u64;
    let mut new_effects_total = 0u64;
    let mut base_fuel_total = 0u64;
    let mut new_fuel_total = 0u64;

    let mut caps_before_set: BTreeSet<String> = BTreeSet::new();
    let mut caps_after_set: BTreeSet<String> = BTreeSet::new();
    let mut traces_hasher = Sha256::new();

    for (idx, trace) in traces.iter().enumerate() {
        trace.verify_integrity()?;
        if trace.lexicon_hash != base_lex_hash {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                format!("trace {} does not belong to base lexicon", idx),
            ));
        }
        traces_hasher.update_hash(&trace.trace_hash);

        let entry = parse_term(arena, &trace.entry_sexpr)?;

        // 1. static capability non-escalation check
        let before_caps = base_lexicon.static_cap_names(arena, entry);
        let after_caps = new_lexicon.static_cap_names(arena, entry);
        for c in &after_caps {
            if !before_caps.contains(c) {
                return Err(Diag::runtime(
                    DiagCode::CapabilityEscalation,
                    format!(
                        "candidate reflex escalates capability '{}' not present in base lexicon",
                        c
                    ),
                ));
            }
        }
        for c in before_caps {
            caps_before_set.insert(c);
        }
        for c in after_caps {
            caps_after_set.insert(c);
        }

        // build deterministic effect oracle from the trace's recorded events
        // supports skipping eliminated effects while answering any retained effects deterministically
        let mut oracle: BTreeMap<Hash256, Vec<TermId>> = BTreeMap::new();
        for ev in &trace.events {
            let reply_term = parse_term(arena, &ev.reply_sexpr)?;
            oracle.entry(ev.effect_hash).or_default().push(reply_term);
        }

        // 2. replay entry under candidate lexicon
        let mut fuel = Fuel::new(trace.fuel_limit);
        let mut cur = entry;
        let mut new_effects = 0u64;

        let new_outcome = loop {
            match eval(arena, &new_lexicon, cur, &mut fuel) {
                Outcome::Done(val) => {
                    break TraceOutcome::Done {
                        value_hash: arena.hash(val),
                        value_sexpr: crate::syntax::print_term(arena, val),
                    };
                }
                Outcome::Exhausted { resume } => {
                    break TraceOutcome::Exhausted {
                        residual_hash: arena.hash(resume),
                        residual_sexpr: crate::syntax::print_term(arena, resume),
                    };
                }
                Outcome::Fault(diag) => {
                    break TraceOutcome::Fault {
                        code: String::from(diag.code.as_str()),
                        message: diag.message,
                    };
                }
                Outcome::Yield { effect, resume } => {
                    let eff_hash = arena.hash(effect);
                    let reply = oracle
                        .get_mut(&eff_hash)
                        .and_then(|queue| if queue.is_empty() { None } else { Some(queue.remove(0)) })
                        .ok_or_else(|| {
                            Diag::runtime(
                                DiagCode::MissingJournalEffect,
                                format!(
                                    "candidate performed unrecorded effect {} on trace {}",
                                    crate::syntax::print_term(arena, effect),
                                    idx
                                ),
                            )
                        })?;
                    new_effects += 1;
                    cur = plug_hole(arena, resume, reply)?;
                }
            }
        };

        // 3. exact output equivalence check
        if new_outcome != trace.outcome {
            return Err(Diag::runtime(
                DiagCode::ReplayDivergence,
                format!("candidate output diverged from recorded trace {}", idx),
            ));
        }

        base_effects_total += trace.events.len() as u64;
        new_effects_total += new_effects;
        base_fuel_total += trace.fuel_used;
        new_fuel_total += fuel.used();
    }

    // 4. strict improvement gate (must eliminate external effects OR reduce fuel)
    let eliminated_effects = new_effects_total < base_effects_total;
    let reduced_fuel = new_fuel_total < base_fuel_total && new_effects_total <= base_effects_total;
    if !eliminated_effects && !reduced_fuel {
        return Err(Diag::runtime(
            DiagCode::NoImprovement,
            format!(
                "candidate did not improve over base (effects: {} -> {}, fuel: {} -> {})",
                base_effects_total, new_effects_total, base_fuel_total, new_fuel_total
            ),
        ));
    }

    let mut cert = CrystalCert {
        base_lexicon_hash: base_lex_hash,
        new_lexicon_hash: new_lex_hash,
        traces_merkle_root: traces_hasher.finalize(),
        trace_count: traces.len() as u32,
        base_effects: base_effects_total,
        new_effects: new_effects_total,
        base_fuel: base_fuel_total,
        new_fuel: new_fuel_total,
        caps_before: caps_before_set.into_iter().collect(),
        caps_after: caps_after_set.into_iter().collect(),
        cert_hash: Hash256::ZERO,
    };
    cert.cert_hash = cert.compute_hash();

    Ok((new_lexicon, cert))
}
