//! durable merkle effect journal, bit-for-bit offline replay, and time-travel forking.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::{Arena, TermId};
use crate::diag::{Diag, DiagCode};
use crate::eval::{eval, plug_hole, Outcome};
use crate::fuel::Fuel;
use crate::hash::{Hash256, Sha256, TAG_EVENT, TAG_TRACE};
use crate::lexicon::Lexicon;
use crate::syntax::{parse_term, print_term};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEvent {
    pub index: u32,
    pub fuel_at_yield: u64,
    pub effect_hash: Hash256,
    pub effect_sexpr: String,
    pub residual_hash: Hash256,
    pub residual_sexpr: String,
    pub reply_hash: Hash256,
    pub reply_sexpr: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceOutcome {
    Done {
        value_hash: Hash256,
        value_sexpr: String,
    },
    Exhausted {
        residual_hash: Hash256,
        residual_sexpr: String,
    },
    Fault {
        code: String,
        message: String,
    },
}

/// a complete, self-contained, cryptographically chained execution trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub lexicon_hash: Hash256,
    pub entry_hash: Hash256,
    pub entry_sexpr: String,
    pub fuel_limit: u64,
    pub fuel_used: u64,
    pub events: Vec<JournalEvent>,
    pub outcome: TraceOutcome,
    pub trace_hash: Hash256,
}

impl Trace {
    pub fn compute_hash(&self) -> Hash256 {
        let mut h = Sha256::new();
        h.update_u8(TAG_TRACE);
        h.update_hash(&self.lexicon_hash);
        h.update_hash(&self.entry_hash);
        h.update_u64(self.fuel_limit);
        h.update_u64(self.fuel_used);
        h.update_u32(self.events.len() as u32);
        for ev in &self.events {
            h.update_u8(TAG_EVENT);
            h.update_u32(ev.index);
            h.update_u64(ev.fuel_at_yield);
            h.update_hash(&ev.effect_hash);
            h.update_hash(&ev.residual_hash);
            h.update_hash(&ev.reply_hash);
        }
        match &self.outcome {
            TraceOutcome::Done { value_hash, .. } => {
                h.update_u8(1);
                h.update_hash(value_hash);
            }
            TraceOutcome::Exhausted { residual_hash, .. } => {
                h.update_u8(2);
                h.update_hash(residual_hash);
            }
            TraceOutcome::Fault { code, message } => {
                h.update_u8(3);
                h.update_len_bytes(code.as_bytes());
                h.update_len_bytes(message.as_bytes());
            }
        }
        h.finalize()
    }

    pub fn verify_integrity(&self) -> Result<(), Diag> {
        let expected = self.compute_hash();
        if expected != self.trace_hash {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                format!(
                    "trace hash mismatch: expected {}, got {}",
                    expected.short_hex(),
                    self.trace_hash.short_hex()
                ),
            ));
        }
        Ok(())
    }

    /// compact zero-dep line-oriented serialization for disk/network portability.
    pub fn encode_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("nacre-trace-v1\n"));
        out.push_str(&format!("lexicon {}\n", self.lexicon_hash.to_hex()));
        out.push_str(&format!("entry_hash {}\n", self.entry_hash.to_hex()));
        out.push_str(&format!("entry {}\n", self.entry_sexpr));
        out.push_str(&format!("fuel_limit {}\n", self.fuel_limit));
        out.push_str(&format!("fuel_used {}\n", self.fuel_used));
        out.push_str(&format!("events {}\n", self.events.len()));
        for ev in &self.events {
            out.push_str(&format!(
                "ev {} {} {} {} {}\n",
                ev.index,
                ev.fuel_at_yield,
                ev.effect_hash.to_hex(),
                ev.residual_hash.to_hex(),
                ev.reply_hash.to_hex()
            ));
            out.push_str(&format!("  eff {}\n", ev.effect_sexpr));
            out.push_str(&format!("  res {}\n", ev.residual_sexpr));
            out.push_str(&format!("  rep {}\n", ev.reply_sexpr));
        }
        match &self.outcome {
            TraceOutcome::Done {
                value_hash,
                value_sexpr,
            } => {
                out.push_str(&format!("outcome done {}\n", value_hash.to_hex()));
                out.push_str(&format!("  val {}\n", value_sexpr));
            }
            TraceOutcome::Exhausted {
                residual_hash,
                residual_sexpr,
            } => {
                out.push_str(&format!("outcome exhausted {}\n", residual_hash.to_hex()));
                out.push_str(&format!("  res {}\n", residual_sexpr));
            }
            TraceOutcome::Fault { code, message } => {
                out.push_str(&format!("outcome fault {} {}\n", code, message));
            }
        }
        out.push_str(&format!("trace_hash {}\n", self.trace_hash.to_hex()));
        out
    }

    pub fn decode_text(input: &str) -> Result<Self, Diag> {
        let lines: Vec<&str> = input.lines().collect();
        let mut idx = 0usize;
        let next_line = |idx: &mut usize| -> Result<&str, Diag> {
            let line = lines
                .get(*idx)
                .copied()
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "truncated trace"))?;
            *idx += 1;
            Ok(line)
        };

        if next_line(&mut idx)? != "nacre-trace-v1" {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                "unsupported trace header",
            ));
        }

        let lexicon_hash = parse_hex_field(next_line(&mut idx)?, "lexicon ")?;
        let entry_hash = parse_hex_field(next_line(&mut idx)?, "entry_hash ")?;
        let entry_sexpr = strip_field(next_line(&mut idx)?, "entry ")?;
        let fuel_limit = parse_u64_field(next_line(&mut idx)?, "fuel_limit ")?;
        let fuel_used = parse_u64_field(next_line(&mut idx)?, "fuel_used ")?;
        let ev_count = parse_u64_field(next_line(&mut idx)?, "events ")? as usize;

        let mut events = Vec::with_capacity(ev_count);
        for _ in 0..ev_count {
            let header = strip_field(next_line(&mut idx)?, "ev ")?;
            let parts: Vec<&str> = header.split_whitespace().collect();
            if parts.len() != 5 {
                return Err(Diag::runtime(
                    DiagCode::JournalHashMismatch,
                    "malformed event header",
                ));
            }
            let index = parts[0]
                .parse::<u32>()
                .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "bad event index"))?;
            let fuel_at_yield = parts[1]
                .parse::<u64>()
                .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "bad event fuel"))?;
            let effect_hash = Hash256::from_hex(parts[2])
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "bad effect hash"))?;
            let residual_hash = Hash256::from_hex(parts[3])
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "bad residual hash"))?;
            let reply_hash = Hash256::from_hex(parts[4])
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "bad reply hash"))?;

            let effect_sexpr = strip_field(next_line(&mut idx)?, "  eff ")?;
            let residual_sexpr = strip_field(next_line(&mut idx)?, "  res ")?;
            let reply_sexpr = strip_field(next_line(&mut idx)?, "  rep ")?;

            events.push(JournalEvent {
                index,
                fuel_at_yield,
                effect_hash,
                effect_sexpr,
                residual_hash,
                residual_sexpr,
                reply_hash,
                reply_sexpr,
            });
        }

        let outcome_line = strip_field(next_line(&mut idx)?, "outcome ")?;
        let outcome = if let Some(rest) = outcome_line.strip_prefix("done ") {
            let value_hash = Hash256::from_hex(rest.trim())
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "bad value hash"))?;
            let value_sexpr = strip_field(next_line(&mut idx)?, "  val ")?;
            TraceOutcome::Done {
                value_hash,
                value_sexpr,
            }
        } else if let Some(rest) = outcome_line.strip_prefix("exhausted ") {
            let residual_hash = Hash256::from_hex(rest.trim()).ok_or_else(|| {
                Diag::runtime(DiagCode::JournalHashMismatch, "bad exhausted hash")
            })?;
            let residual_sexpr = strip_field(next_line(&mut idx)?, "  res ")?;
            TraceOutcome::Exhausted {
                residual_hash,
                residual_sexpr,
            }
        } else if let Some(rest) = outcome_line.strip_prefix("fault ") {
            let mut split = rest.splitn(2, ' ');
            let code = String::from(split.next().unwrap_or("e000"));
            let message = String::from(split.next().unwrap_or(""));
            TraceOutcome::Fault { code, message }
        } else {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                "unknown outcome kind",
            ));
        };

        let trace_hash = parse_hex_field(next_line(&mut idx)?, "trace_hash ")?;
        let trace = Self {
            lexicon_hash,
            entry_hash,
            entry_sexpr,
            fuel_limit,
            fuel_used,
            events,
            outcome,
            trace_hash,
        };
        trace.verify_integrity()?;
        Ok(trace)
    }
}

fn strip_field(line: &str, prefix: &str) -> Result<String, Diag> {
    line.strip_prefix(prefix)
        .map(String::from)
        .ok_or_else(|| {
            Diag::runtime(
                DiagCode::JournalHashMismatch,
                format!("expected prefix '{}'", prefix.trim()),
            )
        })
}

fn parse_hex_field(line: &str, prefix: &str) -> Result<Hash256, Diag> {
    let raw = strip_field(line, prefix)?;
    Hash256::from_hex(raw.trim())
        .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "invalid hex hash"))
}

fn parse_u64_field(line: &str, prefix: &str) -> Result<u64, Diag> {
    let raw = strip_field(line, prefix)?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "invalid integer field"))
}

/// run `entry` inside the outer durable harness, invoking `host_handler` on every yielded effect
/// and recording a complete cryptographically chained `Trace`.
pub fn run_and_record<F>(
    arena: &mut Arena,
    lexicon: &Lexicon,
    entry: TermId,
    fuel_limit: u64,
    mut host_handler: F,
) -> Result<Trace, Diag>
where
    F: FnMut(&mut Arena, TermId) -> Result<TermId, Diag>,
{
    let lexicon_hash = lexicon.hash(arena);
    let entry_hash = arena.hash(entry);
    let entry_sexpr = print_term(arena, entry);
    let mut fuel = Fuel::new(fuel_limit);
    let mut cur = entry;
    let mut events = Vec::new();

    let outcome = loop {
        match eval(arena, lexicon, cur, &mut fuel) {
            Outcome::Done(val) => {
                break TraceOutcome::Done {
                    value_hash: arena.hash(val),
                    value_sexpr: print_term(arena, val),
                };
            }
            Outcome::Exhausted { resume } => {
                break TraceOutcome::Exhausted {
                    residual_hash: arena.hash(resume),
                    residual_sexpr: print_term(arena, resume),
                };
            }
            Outcome::Fault(diag) => {
                break TraceOutcome::Fault {
                    code: String::from(diag.code.as_str()),
                    message: diag.message,
                };
            }
            Outcome::Yield { effect, resume } => {
                let effect_hash = arena.hash(effect);
                let effect_sexpr = print_term(arena, effect);
                let residual_hash = arena.hash(resume);
                let residual_sexpr = print_term(arena, resume);
                let reply = host_handler(arena, effect)?;
                let reply_hash = arena.hash(reply);
                let reply_sexpr = print_term(arena, reply);
                events.push(JournalEvent {
                    index: events.len() as u32,
                    fuel_at_yield: fuel.used(),
                    effect_hash,
                    effect_sexpr,
                    residual_hash,
                    residual_sexpr,
                    reply_hash,
                    reply_sexpr,
                });
                cur = plug_hole(arena, resume, reply)?;
            }
        }
    };

    let mut trace = Trace {
        lexicon_hash,
        entry_hash,
        entry_sexpr,
        fuel_limit,
        fuel_used: fuel.used(),
        events,
        outcome,
        trace_hash: Hash256::ZERO,
    };
    trace.trace_hash = trace.compute_hash();
    Ok(trace)
}

/// strictly replay a recorded trace offline (zero external i/o), proving bit-for-bit
/// equivalence of every effect, residual continuation, fuel delta, and final output.
pub fn replay_trace(arena: &mut Arena, lexicon: &Lexicon, trace: &Trace) -> Result<(), Diag> {
    trace.verify_integrity()?;
    let lex_hash = lexicon.hash(arena);
    if lex_hash != trace.lexicon_hash {
        return Err(Diag::runtime(
            DiagCode::ReplayDivergence,
            format!(
                "lexicon hash mismatch: expected {}, got {}",
                trace.lexicon_hash.short_hex(),
                lex_hash.short_hex()
            ),
        ));
    }

    let entry = parse_term(arena, &trace.entry_sexpr)?;
    if arena.hash(entry) != trace.entry_hash {
        return Err(Diag::runtime(
            DiagCode::ReplayDivergence,
            "entry term hash diverged on replay",
        ));
    }

    let mut fuel = Fuel::new(trace.fuel_limit);
    let mut cur = entry;
    let mut ev_idx = 0usize;

    let actual_outcome = loop {
        match eval(arena, lexicon, cur, &mut fuel) {
            Outcome::Done(val) => {
                break TraceOutcome::Done {
                    value_hash: arena.hash(val),
                    value_sexpr: print_term(arena, val),
                };
            }
            Outcome::Exhausted { resume } => {
                break TraceOutcome::Exhausted {
                    residual_hash: arena.hash(resume),
                    residual_sexpr: print_term(arena, resume),
                };
            }
            Outcome::Fault(diag) => {
                break TraceOutcome::Fault {
                    code: String::from(diag.code.as_str()),
                    message: diag.message,
                };
            }
            Outcome::Yield { effect, resume } => {
                let recorded = trace.events.get(ev_idx).ok_or_else(|| {
                    Diag::runtime(
                        DiagCode::ReplayDivergence,
                        format!("unexpected extra yield at event {}", ev_idx),
                    )
                })?;
                if arena.hash(effect) != recorded.effect_hash {
                    return Err(Diag::runtime(
                        DiagCode::ReplayDivergence,
                        format!("effect hash diverged at event {}", ev_idx),
                    ));
                }
                if arena.hash(resume) != recorded.residual_hash {
                    return Err(Diag::runtime(
                        DiagCode::ReplayDivergence,
                        format!("residual continuation hash diverged at event {}", ev_idx),
                    ));
                }
                if fuel.used() != recorded.fuel_at_yield {
                    return Err(Diag::runtime(
                        DiagCode::ReplayDivergence,
                        format!("fuel diverged at event {}", ev_idx),
                    ));
                }
                let reply = parse_term(arena, &recorded.reply_sexpr)?;
                if arena.hash(reply) != recorded.reply_hash {
                    return Err(Diag::runtime(
                        DiagCode::ReplayDivergence,
                        format!("reply hash mismatch at event {}", ev_idx),
                    ));
                }
                ev_idx += 1;
                cur = plug_hole(arena, resume, reply)?;
            }
        }
    };

    if ev_idx != trace.events.len() {
        return Err(Diag::runtime(
            DiagCode::ReplayDivergence,
            "replay terminated before consuming all recorded events",
        ));
    }
    if fuel.used() != trace.fuel_used {
        return Err(Diag::runtime(
            DiagCode::ReplayDivergence,
            format!(
                "total fuel diverged: expected {}, got {}",
                trace.fuel_used,
                fuel.used()
            ),
        ));
    }
    if actual_outcome != trace.outcome {
        return Err(Diag::runtime(
            DiagCode::ReplayDivergence,
            "final outcome diverged on replay",
        ));
    }
    Ok(())
}

/// time-travel fork: jump directly to event `at_event` using its content-addressed residual
/// continuation, inject `alternate_reply`, and continue execution deterministically.
pub fn fork_from_event<F>(
    arena: &mut Arena,
    lexicon: &Lexicon,
    trace: &Trace,
    at_event: usize,
    alternate_reply: TermId,
    host_handler: F,
) -> Result<Trace, Diag>
where
    F: FnMut(&mut Arena, TermId) -> Result<TermId, Diag>,
{
    trace.verify_integrity()?;
    let ev = trace.events.get(at_event).ok_or_else(|| {
        Diag::runtime(
            DiagCode::MissingJournalEffect,
            format!("event index {} out of bounds", at_event),
        )
    })?;
    let residual = parse_term(arena, &ev.residual_sexpr)?;
    if arena.hash(residual) != ev.residual_hash {
        return Err(Diag::runtime(
            DiagCode::JournalHashMismatch,
            "stored residual hash mismatch",
        ));
    }
    let forked_entry = plug_hole(arena, residual, alternate_reply)?;
    let rem_fuel = trace.fuel_limit.saturating_sub(ev.fuel_at_yield);
    run_and_record(arena, lexicon, forked_entry, rem_fuel, host_handler)
}
