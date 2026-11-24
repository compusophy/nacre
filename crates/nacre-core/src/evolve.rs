//! verifiable multi-generation hill-climber & bottom-up observational-equivalence synthesizer.
//!
//! zero cheating, zero hardcoded task answers, zero floats, zero rng, `#![no_std]`.
//! given only recorded durable merkle traces of an effectful rule `(rule (head ?p...) (perform cap ?p...))`,
//! this module climbs monotonically through verified generations:
//!   - gen 0: baseline effectful lexicon (100% external oracle calls)
//!   - gen 1: hybrid guarded exact-table reflex (safe fallback to oracle on unseen inputs)
//!   - gen 2: exact pure symbolic reflex (recursive recurrence OR bottom-up obs-equiv + stun piecewise)
//!   - gen 3: fuel-minimizing superoptimization (e.g. o(n) recursive -> o(1) closed form)
//!   - gen 4: tier-2 native wasm 1.0 reflex compilation + differential oracle parity check
//!
//! every single promotion is gated mechanically by `crystallize_from_source`; every failed
//! or non-improving candidate is rejected and counted.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::arena::{sym, Arena, Node, SymId};
use crate::diag::{Diag, DiagCode};
use crate::distill::{crystallize_from_source, CrystalCert};
use crate::eval::{eval, Outcome};
use crate::fuel::Fuel;
use crate::hash::Hash256;
use crate::journal::{run_and_record, Trace};
use crate::lexicon::{Lexicon, Pattern};
use crate::syntax::parse_term;
use crate::wasm_emit::{compile_pure_i64_reflex, exec_wasm_reflex, WasmReflex, WASM_STATUS_OK};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClimbStage {
    Gen0Oracle,
    Gen1HybridTable,
    Gen2PureRecursive,
    Gen3PureClosedForm,
    Gen4WasmReflex,
}

impl ClimbStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Gen0Oracle => "gen0_oracle",
            Self::Gen1HybridTable => "gen1_hybrid_table",
            Self::Gen2PureRecursive => "gen2_pure_recursive",
            Self::Gen3PureClosedForm => "gen3_pure_closed_form",
            Self::Gen4WasmReflex => "gen4_wasm_reflex",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenerationStep {
    pub stage: ClimbStage,
    pub rule_src: String,
    pub lexicon_hash: Hash256,
    pub cert: Option<CrystalCert>,
    pub train_effects: u64,
    pub train_fuel: u64,
    pub is_pure: bool,
}

#[derive(Clone, Debug)]
pub struct HillClimbReport {
    pub target_head: String,
    pub arity: usize,
    pub history: Vec<GenerationStep>,
    pub final_lexicon: Lexicon,
    pub wasm_reflex: Option<WasmReflex>,
    pub candidates_evaluated: u64,
    pub candidates_pruned_obs_equiv: u64,
    pub gate_rejections: u64,
}

impl HillClimbReport {
    pub fn final_stage(&self) -> ClimbStage {
        if self.wasm_reflex.is_some() {
            ClimbStage::Gen4WasmReflex
        } else {
            self.history
                .last()
                .map(|g| g.stage)
                .unwrap_or(ClimbStage::Gen0Oracle)
        }
    }
}

/// run a genuine multi-generation verifier-gated hill-climb from recorded traces alone.
///
/// works for any 1-arity or 2-arity integer delegating rule:
/// `(rule (head ?p0) (perform cap ?p0))` or `(rule (head ?p0 ?p1) (perform cap ?p0 ?p1))`.
pub fn hill_climb_integer_task(
    arena: &mut Arena,
    base_lexicon: &Lexicon,
    base_traces: &[Trace],
    target_head_name: &str,
) -> Result<HillClimbReport, Diag> {
    if base_traces.is_empty() {
        return Err(Diag::runtime(
            DiagCode::EmptyTraceSet,
            "hill_climb requires at least one recorded trace",
        ));
    }
    let target_head = arena.lookup_sym(target_head_name).ok_or_else(|| {
        Diag::runtime(
            DiagCode::InvalidRuleForm,
            format!("unknown rule '{}'", target_head_name),
        )
    })?;

    // detect arity and delegated capability from the base lexicon
    let (arity, cap_sym) = detect_delegating_rule(arena, base_lexicon, target_head)?;
    let cap_name = String::from(arena.sym_name(cap_sym));

    // extract pure (input_ints, output_int) observations strictly from recorded trace events
    let samples = extract_int_samples(arena, base_traces, cap_sym, arity)?;
    if samples.is_empty() {
        return Err(Diag::runtime(
            DiagCode::EmptyTraceSet,
            "no integer effect samples found in traces",
        ));
    }

    let base_effects: u64 = base_traces.iter().map(|t| t.events.len() as u64).sum();
    let base_fuel: u64 = base_traces.iter().map(|t| t.fuel_used).sum();

    let mut cur_lex = base_lexicon.clone();
    let mut cur_traces: Vec<Trace> = base_traces.to_vec();
    let mut history = vec![GenerationStep {
        stage: ClimbStage::Gen0Oracle,
        rule_src: format!(
            "(rule ({} {}) (perform {} {}))",
            target_head_name,
            param_list_str(arity),
            cap_name,
            param_list_str(arity)
        ),
        lexicon_hash: cur_lex.hash(arena),
        cert: None,
        train_effects: base_effects,
        train_fuel: base_fuel,
        is_pure: false,
    }];

    let mut candidates_evaluated = 0u64;
    let mut candidates_pruned_obs_equiv = 0u64;
    let mut gate_rejections = 0u64;

    // -----------------------------------------------------------------------
    // GEN 1: safe hybrid exact-table reflex (falls back to oracle on unseen)
    // -----------------------------------------------------------------------
    let hybrid_src = build_hybrid_table_rule(target_head_name, &cap_name, arity, &samples);
    candidates_evaluated += 1;
    match crystallize_from_source(arena, &cur_lex, &cur_traces, &hybrid_src) {
        Ok((next_lex, cert)) => {
            cur_traces = re_record_traces_offline(arena, &next_lex, base_traces)?;
            history.push(GenerationStep {
                stage: ClimbStage::Gen1HybridTable,
                rule_src: hybrid_src,
                lexicon_hash: cert.new_lexicon_hash,
                train_effects: cert.new_effects,
                train_fuel: cert.new_fuel,
                is_pure: cert.is_now_pure(),
                cert: Some(cert),
            });
            cur_lex = next_lex;
        }
        Err(_) => {
            gate_rejections += 1;
        }
    }

    // -----------------------------------------------------------------------
    // GEN 2: discover pure recursive supercombinator (for unary sequential tasks)
    // -----------------------------------------------------------------------
    if arity == 1 {
        let rec_candidates = synthesize_recursive_candidates(target_head_name, &samples);
        for cand_src in rec_candidates {
            candidates_evaluated += 1;
            // verify against the original base_traces (must eliminate ALL oracle calls!)
            // and if already pure, must strictly beat current fuel
            match crystallize_from_source(arena, base_lexicon, base_traces, &cand_src) {
                Ok((next_lex, cert)) if cert.is_now_pure() => {
                    let next_traces = re_record_traces_offline(arena, &next_lex, base_traces)?;
                    history.push(GenerationStep {
                        stage: ClimbStage::Gen2PureRecursive,
                        rule_src: cand_src,
                        lexicon_hash: cert.new_lexicon_hash,
                        train_effects: cert.new_effects,
                        train_fuel: cert.new_fuel,
                        is_pure: true,
                        cert: Some(cert),
                    });
                    cur_lex = next_lex;
                    cur_traces = next_traces;
                    break;
                }
                _ => {
                    gate_rejections += 1;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // GEN 3: bottom-up observational-equivalence synthesis + STUN piecewise
    // uses an internal journal train/validation split (~75% / ~25%) so coincidental
    // overfitting expressions (e.g. piecewise hacks over small recursive prefixes or
    // non-expressible functions like primality) are rejected mechanically before promotion!
    // -----------------------------------------------------------------------
    let synth = bottom_up_synthesize_validated(&samples, arity);
    candidates_evaluated += synth.evaluated;
    candidates_pruned_obs_equiv += synth.pruned;

    if let Some(expr) = synth.found {
        let closed_src = format!(
            "(rule ({} {}) {})",
            target_head_name,
            param_list_str(arity),
            expr.to_sexpr()
        );
        candidates_evaluated += 1;
        // gate strictly against CURRENT lexicon/traces if we already promoted a pure recursive rule
        // (so Gen 3 is ONLY accepted if it strictly reduces fuel over Gen 2!),
        // or against base_lexicon/base_traces if coming from Gen 0/1 (eliminating all oracle calls!).
        let already_pure = history.last().map(|g| g.is_pure).unwrap_or(false);
        let gate_res = if already_pure {
            crystallize_from_source(arena, &cur_lex, &cur_traces, &closed_src)
        } else {
            crystallize_from_source(arena, base_lexicon, base_traces, &closed_src)
        };

        match gate_res {
            Ok((next_lex, cert)) if cert.is_now_pure() => {
                history.push(GenerationStep {
                    stage: ClimbStage::Gen3PureClosedForm,
                    rule_src: closed_src,
                    lexicon_hash: cert.new_lexicon_hash,
                    train_effects: cert.new_effects,
                    train_fuel: cert.new_fuel,
                    is_pure: true,
                    cert: Some(cert),
                });
                cur_lex = next_lex;
            }
            _ => {
                gate_rejections += 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // GEN 4: tier-2 native wasm 1.0 compilation + differential oracle verification
    // -----------------------------------------------------------------------
    let mut wasm_reflex = None;
    let is_final_pure = history.last().map(|g| g.is_pure).unwrap_or(false);
    if is_final_pure {
        if let Ok(reflex) = compile_pure_i64_reflex(arena, &cur_lex, target_head) {
            // differential oracle verification over EVERY training sample
            let mut all_match = true;
            for (args, expected) in &samples {
                match exec_wasm_reflex(&reflex.wasm_bytes, args, 100_000) {
                    Ok(res) if res.status == WASM_STATUS_OK && res.value == *expected => {}
                    _ => {
                        all_match = false;
                        break;
                    }
                }
            }
            if all_match {
                wasm_reflex = Some(reflex);
            } else {
                gate_rejections += 1;
            }
        }
    }

    Ok(HillClimbReport {
        target_head: String::from(target_head_name),
        arity,
        history,
        final_lexicon: cur_lex,
        wasm_reflex,
        candidates_evaluated,
        candidates_pruned_obs_equiv,
        gate_rejections,
    })
}

fn detect_delegating_rule(
    arena: &Arena,
    lexicon: &Lexicon,
    head: SymId,
) -> Result<(usize, SymId), Diag> {
    let clauses = lexicon.rules_for(head).ok_or_else(|| {
        Diag::runtime(DiagCode::InvalidRuleForm, "target head not found in lexicon")
    })?;
    if clauses.len() != 1 {
        return Err(Diag::runtime(
            DiagCode::InvalidRuleForm,
            "baseline rule must have exactly one delegating clause",
        ));
    }
    let rule = &clauses[0];
    let arity = rule.params.len();
    if arity == 0 || arity > 2 {
        return Err(Diag::runtime(
            DiagCode::ArityMismatch,
            "hill_climb supports 1-arity or 2-arity rules",
        ));
    }
    for p in &rule.params {
        if !matches!(p, Pattern::Var(_)) {
            return Err(Diag::runtime(
                DiagCode::InvalidPattern,
                "baseline delegating rule params must be variables",
            ));
        }
    }
    if let Node::App(bh, bargs) = arena.node(rule.body) {
        if *bh == sym::PERFORM && bargs.len() == 1 + arity {
            if let Node::Sym(cap) = arena.node(bargs[0]) {
                return Ok((arity, *cap));
            }
        }
    }
    Err(Diag::runtime(
        DiagCode::InvalidRuleForm,
        "baseline rule body must be (perform <cap> ?p0 ...)",
    ))
}

fn extract_int_samples(
    arena: &mut Arena,
    traces: &[Trace],
    cap_sym: SymId,
    arity: usize,
) -> Result<Vec<(Vec<i64>, i64)>, Diag> {
    let mut map: BTreeMap<Vec<i64>, i64> = BTreeMap::new();
    for tr in traces {
        for ev in &tr.events {
            let eff = parse_term(arena, &ev.effect_sexpr)?;
            let rep = parse_term(arena, &ev.reply_sexpr)?;
            if let (Node::App(eh, eargs), Node::Int(out_v)) =
                (arena.node(eff).clone(), arena.node(rep).clone())
            {
                if eh == cap_sym && eargs.len() == arity {
                    let mut xs = Vec::with_capacity(arity);
                    let mut ok = true;
                    for &a in eargs.iter() {
                        if let Node::Int(v) = arena.node(a) {
                            xs.push(*v);
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        map.insert(xs, out_v);
                    }
                }
            }
        }
    }
    Ok(map.into_iter().collect())
}

fn param_list_str(arity: usize) -> String {
    match arity {
        1 => String::from("?p0"),
        2 => String::from("?p0 ?p1"),
        _ => String::new(),
    }
}

fn build_hybrid_table_rule(
    head: &str,
    cap: &str,
    arity: usize,
    samples: &[(Vec<i64>, i64)],
) -> String {
    let mut out = String::new();
    for (args, y) in samples {
        let arg_s: Vec<String> = args.iter().map(|v| format!("{}", v)).collect();
        out.push_str(&format!("(rule ({} {}) {})\n", head, arg_s.join(" "), y));
    }
    let ps = param_list_str(arity);
    out.push_str(&format!("(rule ({} {}) (perform {} {}))", head, ps, cap, ps));
    out
}

fn re_record_traces_offline(
    arena: &mut Arena,
    lexicon: &Lexicon,
    base_traces: &[Trace],
) -> Result<Vec<Trace>, Diag> {
    let mut out = Vec::with_capacity(base_traces.len());
    for bt in base_traces {
        let mut oracle: BTreeMap<Hash256, String> = BTreeMap::new();
        for ev in &bt.events {
            oracle.insert(ev.effect_hash, ev.reply_sexpr.clone());
        }
        let entry = parse_term(arena, &bt.entry_sexpr)?;
        let tr = run_and_record(arena, lexicon, entry, bt.fuel_limit, |a, eff| {
            let h = a.hash(eff);
            let rep_s = oracle.get(&h).ok_or_else(|| {
                Diag::runtime(DiagCode::MissingJournalEffect, "missing oracle reply")
            })?;
            parse_term(a, rep_s)
        })?;
        out.push(tr);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// recursive recurrence discovery (purely from observed sequential samples)
// ---------------------------------------------------------------------------

fn synthesize_recursive_candidates(head: &str, samples: &[(Vec<i64>, i64)]) -> Vec<String> {
    let mut table: BTreeMap<i64, i64> = BTreeMap::new();
    for (xs, y) in samples {
        table.insert(xs[0], *y);
    }
    let Some(&y0) = table.get(&0) else {
        return Vec::new();
    };
    let mut found = Vec::new();

    // check 1-step recurrences on n >= 1 where (n-1) is also in the journal
    let step1_pts: Vec<(i64, i64, i64)> = table
        .iter()
        .filter_map(|(&n, &y)| {
            if n >= 1 {
                table.get(&(n - 1)).map(|&prev| (n, prev, y))
            } else {
                None
            }
        })
        .collect();

    if step1_pts.len() >= 4 {
        let ops: &[(&str, fn(i64, i64) -> Option<i64>)] = &[
            ("add", |n, prev| n.checked_add(prev)),
            ("mul", |n, prev| n.checked_mul(prev)),
        ];
        // try `(op ?p0 (head (sub ?p0 1)))`
        for &(op_name, op_fn) in ops {
            if step1_pts
                .iter()
                .all(|&(n, prev, y)| op_fn(n, prev) == Some(y))
            {
                found.push(format!(
                    "(rule ({h} 0) {y0})\n(rule ({h} ?p0) ({op} ?p0 ({h} (sub ?p0 1))))",
                    h = head,
                    y0 = y0,
                    op = op_name
                ));
            }
        }
        // try `(add c (head (sub ?p0 1)))` or `(mul c (head (sub ?p0 1)))` for small c
        for c in [1i64, 2, 3] {
            if step1_pts
                .iter()
                .all(|&(_, prev, y)| prev.checked_mul(c) == Some(y))
            {
                found.push(format!(
                    "(rule ({h} 0) {y0})\n(rule ({h} ?p0) (mul {c} ({h} (sub ?p0 1))))",
                    h = head,
                    y0 = y0,
                    c = c
                ));
            }
        }
    }

    // check 2-step recurrences on n >= 2 where (n-1) and (n-2) are in the journal
    if let Some(&y1) = table.get(&1) {
        let step2_pts: Vec<(i64, i64, i64)> = table
            .iter()
            .filter_map(|(&n, &y)| {
                if n >= 2 {
                    match (table.get(&(n - 1)), table.get(&(n - 2))) {
                        (Some(&p1), Some(&p2)) => Some((p1, p2, y)),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect();
        if step2_pts.len() >= 4
            && step2_pts
                .iter()
                .all(|&(p1, p2, y)| p1.checked_add(p2) == Some(y))
        {
            found.push(format!(
                "(rule ({h} 0) {y0})\n(rule ({h} 1) {y1})\n(rule ({h} ?p0) (add ({h} (sub ?p0 1)) ({h} (sub ?p0 2))))",
                h = head,
                y0 = y0,
                y1 = y1
            ));
        }
    }

    found
}

// ---------------------------------------------------------------------------
// bottom-up observational-equivalence integer + STUN piecewise synthesizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl BinOp {
    fn name(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Mod => "mod",
        }
    }
    fn eval(&self, a: i64, b: i64) -> Option<i64> {
        match self {
            Self::Add => a.checked_add(b),
            Self::Sub => a.checked_sub(b),
            Self::Mul => a.checked_mul(b),
            Self::Div => {
                if b == 0 {
                    None
                } else {
                    a.checked_div(b)
                }
            }
            Self::Mod => {
                if b == 0 {
                    None
                } else {
                    a.checked_rem(b)
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum CmpOp {
    Eq,
    Lt,
    Le,
}

impl CmpOp {
    fn name(&self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
    fn eval(&self, a: i64, b: i64) -> bool {
        match self {
            Self::Eq => a == b,
            Self::Lt => a < b,
            Self::Le => a <= b,
        }
    }
}

#[derive(Clone, Debug)]
struct Cond {
    op: CmpOp,
    lhs: Box<Expr>,
    rhs: Box<Expr>,
}

impl Cond {
    fn to_sexpr(&self) -> String {
        format!(
            "({} {} {})",
            self.op.name(),
            self.lhs.to_sexpr(),
            self.rhs.to_sexpr()
        )
    }
}

#[derive(Clone, Debug)]
enum Expr {
    Const(i64),
    Var(usize),
    Neg(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    If(Cond, Box<Expr>, Box<Expr>),
}

impl Expr {
    fn to_sexpr(&self) -> String {
        match self {
            Self::Const(v) => format!("{}", v),
            Self::Var(i) => format!("?p{}", i),
            Self::Neg(e) => format!("(neg {})", e.to_sexpr()),
            Self::Bin(op, l, r) => format!("({} {} {})", op.name(), l.to_sexpr(), r.to_sexpr()),
            Self::If(c, t, f) => format!("(if {} {} {})", c.to_sexpr(), t.to_sexpr(), f.to_sexpr()),
        }
    }
}

struct SynthResult {
    found: Option<Expr>,
    evaluated: u64,
    pruned: u64,
}

impl Expr {
    fn eval_on(&self, xs: &[i64]) -> Option<i64> {
        match self {
            Self::Const(v) => Some(*v),
            Self::Var(i) => xs.get(*i).copied(),
            Self::Neg(e) => e.eval_on(xs)?.checked_neg(),
            Self::Bin(op, l, r) => op.eval(l.eval_on(xs)?, r.eval_on(xs)?),
            Self::If(c, t, f) => {
                let lv = c.lhs.eval_on(xs)?;
                let rv = c.rhs.eval_on(xs)?;
                if c.op.eval(lv, rv) {
                    t.eval_on(xs)
                } else {
                    f.eval_on(xs)
                }
            }
        }
    }
}

/// synthesize on an internal train prefix and mechanically validate on held-back journal points
/// (plus full-set confirmation) to reject coincidental overfitting without touching external test data.
fn bottom_up_synthesize_validated(samples: &[(Vec<i64>, i64)], arity: usize) -> SynthResult {
    // 1. try pure closed-form algebraic expressions (zero `if` branches) on ALL samples first:
    //    a small size <= 4 pure arithmetic formula over >= 6 points has strong MDL compression.
    let pure_res = bottom_up_pure_expr(samples, arity);
    if pure_res.found.is_some() {
        return pure_res;
    }

    // 2. for piecewise `if` synthesis (higher VC dimension -> risk of overfitting),
    //    require passing an internal journal holdout split (synthesize on ~75%, verify on ~25%)!
    //    stratified non-singleton rule: never hold out a singleton output class (e.g. sign(0)=0
    //    when 0 appears once), because removing the sole witness of a class makes it unlearnable.
    if samples.len() < 6 {
        return pure_res;
    }
    let mut class_counts: BTreeMap<i64, usize> = BTreeMap::new();
    for &(_, y) in samples {
        *class_counts.entry(y).or_insert(0) += 1;
    }
    let mut train_sub = Vec::new();
    let mut val_sub = Vec::new();
    let mut class_seen: BTreeMap<i64, usize> = BTreeMap::new();
    for s in samples {
        let y = s.1;
        let total_for_y = class_counts[&y];
        let seen_idx = *class_seen.entry(y).or_insert(0);
        *class_seen.get_mut(&y).unwrap() += 1;
        // hold out every 3rd occurrence of classes with >=2 witnesses (keeps >=1 in train!)
        if total_for_y >= 2 && (seen_idx % 3 == 1) {
            val_sub.push(s.clone());
        } else {
            train_sub.push(s.clone());
        }
    }
    // if every output is unique (regression-like piecewise, e.g. abs/clamp/collatz), fall back to i % 4 == 3
    if val_sub.is_empty() {
        train_sub.clear();
        for (i, s) in samples.iter().enumerate() {
            if i % 4 == 3 {
                val_sub.push(s.clone());
            } else {
                train_sub.push(s.clone());
            }
        }
    }
    let stun_res = bottom_up_stun_piecewise(&train_sub, arity);
    let total_eval = pure_res.evaluated + stun_res.evaluated;
    let total_pruned = pure_res.pruned + stun_res.pruned;

    if let Some(cand) = stun_res.found {
        // verify candidate generalizes to EVERY internal validation point AND all samples!
        let passes_val = val_sub
            .iter()
            .all(|(xs, expected)| cand.eval_on(xs) == Some(*expected));
        if passes_val {
            return SynthResult {
                found: Some(cand),
                evaluated: total_eval,
                pruned: total_pruned,
            };
        }
    }

    SynthResult {
        found: None,
        evaluated: total_eval,
        pruned: total_pruned,
    }
}

fn bottom_up_pure_expr(samples: &[(Vec<i64>, i64)], arity: usize) -> SynthResult {
    let (found, _levels, evaluated, pruned) = run_bottom_up_levels(samples, arity, true);
    SynthResult {
        found,
        evaluated,
        pruned,
    }
}

fn bottom_up_stun_piecewise(samples: &[(Vec<i64>, i64)], arity: usize) -> SynthResult {
    let (found, levels, mut evaluated, pruned) = run_bottom_up_levels(samples, arity, false);
    if found.is_some() {
        return SynthResult {
            found,
            evaluated,
            pruned,
        };
    }

    let target: Vec<i64> = samples.iter().map(|(_, y)| *y).collect();
    let mut term_pool: Vec<(Expr, Vec<i64>)> = Vec::new();
    for s in 1..=3usize {
        term_pool.extend(levels[s].iter().cloned());
    }

    let mut pred_terms: Vec<(Expr, Vec<i64>)> = Vec::new();
    pred_terms.extend(levels[1].iter().cloned());
    for (e, vs) in &levels[2] {
        if matches!(e, Expr::Bin(BinOp::Mod, _, _)) {
            pred_terms.push((e.clone(), vs.clone()));
        }
    }

    let mut preds: Vec<(Cond, Vec<bool>)> = Vec::new();
    let mut seen_pred_masks: BTreeMap<Vec<bool>, ()> = BTreeMap::new();
    // order inequality predicates (lt, le) before equality (eq) to prefer interval splits
    // over single-point memorization!
    let cmp_ops = [CmpOp::Lt, CmpOp::Le, CmpOp::Eq];

    for op in &cmp_ops {
        for (le, lvs) in &pred_terms {
            for (re, rvs) in &pred_terms {
                if lvs == rvs {
                    continue;
                }
                let mask: Vec<bool> = lvs
                    .iter()
                    .zip(rvs.iter())
                    .map(|(&a, &b)| op.eval(a, b))
                    .collect();
                if mask.iter().all(|&b| b) || mask.iter().all(|&b| !b) {
                    continue;
                }
                if seen_pred_masks.insert(mask.clone(), ()).is_some() {
                    continue;
                }
                preds.push((
                    Cond {
                        op: op.clone(),
                        lhs: Box::new(le.clone()),
                        rhs: Box::new(re.clone()),
                    },
                    mask,
                ));
            }
        }
    }

    let all_idx: Vec<usize> = (0..samples.len()).collect();
    if let Some(piecewise) = stun_unify(&all_idx, &target, &term_pool, &preds, 2, &mut evaluated) {
        return SynthResult {
            found: Some(piecewise),
            evaluated,
            pruned,
        };
    }

    SynthResult {
        found: None,
        evaluated,
        pruned,
    }
}

fn run_bottom_up_levels(
    samples: &[(Vec<i64>, i64)],
    arity: usize,
    search_level4: bool,
) -> (Option<Expr>, Vec<Vec<(Expr, Vec<i64>)>>, u64, u64) {
    let target: Vec<i64> = samples.iter().map(|(_, y)| *y).collect();
    let mut evaluated = 0u64;
    let mut pruned = 0u64;

    let mut bank: BTreeMap<Vec<i64>, Expr> = BTreeMap::new();
    let mut levels: Vec<Vec<(Expr, Vec<i64>)>> = vec![Vec::new(); 5];

    let register = |size: usize,
                    expr: Expr,
                    vals: Vec<i64>,
                    bank: &mut BTreeMap<Vec<i64>, Expr>,
                    levels: &mut [Vec<(Expr, Vec<i64>)>],
                    evaluated: &mut u64,
                    pruned: &mut u64|
     -> Option<Expr> {
        *evaluated += 1;
        if vals == target {
            return Some(expr);
        }
        if bank.contains_key(&vals) {
            *pruned += 1;
            return None;
        }
        bank.insert(vals.clone(), expr.clone());
        if size < levels.len() {
            levels[size].push((expr, vals));
        }
        None
    };

    for i in 0..arity {
        let vals: Vec<i64> = samples.iter().map(|(xs, _)| xs[i]).collect();
        if let Some(hit) = register(
            1,
            Expr::Var(i),
            vals,
            &mut bank,
            &mut levels,
            &mut evaluated,
            &mut pruned,
        ) {
            return (Some(hit), levels, evaluated, pruned);
        }
    }
    for c in [0i64, 1, 2, 3, 7, 10, -1] {
        let vals = vec![c; samples.len()];
        if let Some(hit) = register(
            1,
            Expr::Const(c),
            vals,
            &mut bank,
            &mut levels,
            &mut evaluated,
            &mut pruned,
        ) {
            return (Some(hit), levels, evaluated, pruned);
        }
    }

    let lvl1 = levels[1].clone();
    for (e, vs) in &lvl1 {
        if let Some(neg_vs) = vs.iter().map(|&v| v.checked_neg()).collect::<Option<Vec<_>>>() {
            if let Some(hit) = register(
                2,
                Expr::Neg(Box::new(e.clone())),
                neg_vs,
                &mut bank,
                &mut levels,
                &mut evaluated,
                &mut pruned,
            ) {
                return (Some(hit), levels, evaluated, pruned);
            }
        }
    }

    let bin_ops = [BinOp::Add, BinOp::Sub, BinOp::Mul, BinOp::Div, BinOp::Mod];
    let max_size = if search_level4 { 4 } else { 3 };
    const MAX_STORED_PER_LEVEL: usize = 900;

    for total_size in 2..=max_size {
        for l_size in 1..total_size {
            let r_size = total_size - l_size;
            let lefts = levels[l_size].clone();
            let rights = levels[r_size].clone();
            for (le, lvs) in &lefts {
                for (re, rvs) in &rights {
                    for op in &bin_ops {
                        if let Some(out_vs) = lvs
                            .iter()
                            .zip(rvs.iter())
                            .map(|(&a, &b)| op.eval(a, b))
                            .collect::<Option<Vec<_>>>()
                        {
                            if total_size == 4 {
                                evaluated += 1;
                                if out_vs == target {
                                    return (
                                        Some(Expr::Bin(
                                            op.clone(),
                                            Box::new(le.clone()),
                                            Box::new(re.clone()),
                                        )),
                                        levels,
                                        evaluated,
                                        pruned,
                                    );
                                }
                            } else if levels[total_size].len() < MAX_STORED_PER_LEVEL {
                                if let Some(hit) = register(
                                    total_size,
                                    Expr::Bin(
                                        op.clone(),
                                        Box::new(le.clone()),
                                        Box::new(re.clone()),
                                    ),
                                    out_vs,
                                    &mut bank,
                                    &mut levels,
                                    &mut evaluated,
                                    &mut pruned,
                                ) {
                                    return (Some(hit), levels, evaluated, pruned);
                                }
                            } else {
                                evaluated += 1;
                                if out_vs == target {
                                    return (
                                        Some(Expr::Bin(
                                            op.clone(),
                                            Box::new(le.clone()),
                                            Box::new(re.clone()),
                                        )),
                                        levels,
                                        evaluated,
                                        pruned,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (None, levels, evaluated, pruned)
}

fn stun_unify(
    indices: &[usize],
    target: &[i64],
    term_pool: &[(Expr, Vec<i64>)],
    preds: &[(Cond, Vec<bool>)],
    max_depth: usize,
    evaluated: &mut u64,
) -> Option<Expr> {
    // base case: single expression matches every index in `indices`
    for (expr, vals) in term_pool {
        *evaluated += 1;
        if indices.iter().all(|&i| vals[i] == target[i]) {
            return Some(expr.clone());
        }
    }
    if max_depth == 0 {
        return None;
    }

    // try splitting `indices` with a predicate where at least one side is immediately solved by a leaf!
    for (cond, mask) in preds {
        let yes: Vec<usize> = indices.iter().copied().filter(|&i| mask[i]).collect();
        let no: Vec<usize> = indices.iter().copied().filter(|&i| !mask[i]).collect();
        if yes.is_empty() || no.is_empty() {
            continue;
        }
        // prefer clean splits where `yes` is solved directly by a leaf expression
        if let Some(yes_leaf) = term_pool
            .iter()
            .find(|(_, vals)| yes.iter().all(|&i| vals[i] == target[i]))
            .map(|(e, _)| e.clone())
        {
            if let Some(no_expr) =
                stun_unify(&no, target, term_pool, preds, max_depth - 1, evaluated)
            {
                return Some(Expr::If(
                    cond.clone(),
                    Box::new(yes_leaf),
                    Box::new(no_expr),
                ));
            }
        }
    }
    None
}

/// helper: evaluate a rule on a list of unseen held-out `(args, expected)` test points,
/// returning `(exact_matches, offline_handled, escalated_to_oracle, wrong_answers, total_fuel)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldOutScore {
    pub total: usize,
    pub offline_exact: usize,
    pub offline_wrong: usize,
    pub escalated_safe: usize,
    pub faults: usize,
    pub total_fuel: u64,
}

pub fn eval_held_out_int(
    arena: &mut Arena,
    lexicon: &Lexicon,
    head_name: &str,
    held_out: &[(Vec<i64>, i64)],
    fuel_per_case: u64,
) -> HeldOutScore {
    let mut score = HeldOutScore {
        total: held_out.len(),
        offline_exact: 0,
        offline_wrong: 0,
        escalated_safe: 0,
        faults: 0,
        total_fuel: 0,
    };
    for (args, expected) in held_out {
        let arg_s: Vec<String> = args.iter().map(|v| format!("{}", v)).collect();
        let src = format!("({} {})", head_name, arg_s.join(" "));
        let Ok(expr) = parse_term(arena, &src) else {
            score.faults += 1;
            continue;
        };
        let mut fuel = Fuel::new(fuel_per_case);
        match eval(arena, lexicon, expr, &mut fuel) {
            Outcome::Done(v) => {
                score.total_fuel += fuel.used();
                match arena.node(v) {
                    Node::Int(actual) if *actual == *expected => score.offline_exact += 1,
                    _ => score.offline_wrong += 1,
                }
            }
            Outcome::Yield { .. } => {
                score.total_fuel += fuel.used();
                score.escalated_safe += 1;
            }
            Outcome::Exhausted { .. } | Outcome::Fault(_) => {
                score.total_fuel += fuel.used();
                score.faults += 1;
            }
        }
    }
    score
}
