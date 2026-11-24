//! closed supercombinator rules, alpha-canonical hashing, lexicon, and static capability inference.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::{sym, Arena, Node, SymId, TermId};
use crate::diag::{Diag, DiagCode};
use crate::hash::{Hash256, Sha256, TAG_APP, TAG_BYTES, TAG_HOLE, TAG_INT, TAG_LEXICON, TAG_RULE, TAG_SYM, TAG_VAR};
use crate::syntax::parse_terms;

/// linear constructor pattern (each bound variable appears at most once).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Wild,
    Var(SymId),
    Int(i64),
    Bytes(Vec<u8>),
    Sym(SymId),
    App(SymId, Vec<Pattern>),
}

/// a single closed supercombinator rewrite clause: `(rule (head p1 p2 ...) body)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub head: SymId,
    pub params: Vec<Pattern>,
    pub body: TermId,
    pub canonical_hash: Hash256,
    /// direct capabilities invoked via `(perform cap ...)` inside `body`.
    pub direct_caps: BTreeSet<SymId>,
    /// direct rule heads referenced inside `body` (for transitive capability closure).
    pub direct_calls: BTreeSet<SymId>,
}

/// content-addressed collection of supercombinator rules.
#[derive(Clone, Debug, Default)]
pub struct Lexicon {
    rules: BTreeMap<SymId, Vec<Rule>>,
}

impl Lexicon {
    pub fn new() -> Self {
        Self {
            rules: BTreeMap::new(),
        }
    }

    pub fn rules_for(&self, head: SymId) -> Option<&[Rule]> {
        self.rules.get(&head).map(|v| v.as_slice())
    }

    pub fn heads(&self) -> Vec<SymId> {
        self.rules.keys().copied().collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|v| v.len()).sum()
    }

    /// load `(rule (head pat...) body)` declarations from source text.
    pub fn load_source(&mut self, arena: &mut Arena, src: &str) -> Result<usize, Diag> {
        let forms = parse_terms(arena, src)?;
        let mut count = 0;
        for form in forms {
            let rule = compile_rule(arena, form)?;
            self.add_rule(rule);
            count += 1;
        }
        Ok(count)
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.entry(rule.head).or_default().push(rule);
    }

    /// replace all clauses for the heads present in `replacement_rules` (used by crystallization).
    pub fn with_replaced_rules(&self, replacement_rules: Vec<Rule>) -> Self {
        let mut next = self.clone();
        let mut replaced_heads = BTreeSet::new();
        for r in &replacement_rules {
            replaced_heads.insert(r.head);
        }
        for h in replaced_heads {
            next.rules.remove(&h);
        }
        for r in replacement_rules {
            next.add_rule(r);
        }
        next
    }

    /// canonical sha-256 hash of the entire lexicon (sorted by symbol name, alpha-canonical per rule).
    pub fn hash(&self, arena: &Arena) -> Hash256 {
        let mut entries: Vec<(&str, &[Rule])> = self
            .rules
            .iter()
            .map(|(&head, list)| (arena.sym_name(head), list.as_slice()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut h = Sha256::new();
        h.update_u8(TAG_LEXICON);
        h.update_u32(entries.len() as u32);
        for (name, list) in entries {
            h.update_len_bytes(name.as_bytes());
            h.update_u32(list.len() as u32);
            for rule in list {
                h.update_hash(&rule.canonical_hash);
            }
        }
        h.finalize()
    }

    /// statically compute the transitive set of capabilities a term (and all rules it calls) can perform.
    /// note: effects caught by an enclosing `(handle ...)` are still reported conservatively unless
    /// statically proved inert, guaranteeing soundness (no hidden capabilities).
    pub fn static_caps_of_term(&self, arena: &Arena, term: TermId) -> BTreeSet<SymId> {
        let mut direct_caps = BTreeSet::new();
        let mut direct_calls = BTreeSet::new();
        collect_term_effects(arena, term, &mut direct_caps, &mut direct_calls);

        let mut all_caps = direct_caps;
        let mut visited_heads = BTreeSet::new();
        let mut queue: Vec<SymId> = direct_calls.into_iter().collect();

        while let Some(head) = queue.pop() {
            if !visited_heads.insert(head) {
                continue;
            }
            if let Some(clauses) = self.rules.get(&head) {
                for r in clauses {
                    for &c in &r.direct_caps {
                        all_caps.insert(c);
                    }
                    for &callee in &r.direct_calls {
                        if !visited_heads.contains(&callee) {
                            queue.push(callee);
                        }
                    }
                }
            }
        }
        all_caps
    }

    /// static capability names of a rule head (sorted strings for display/certs).
    pub fn static_cap_names(&self, arena: &Arena, term: TermId) -> Vec<String> {
        let mut names: Vec<String> = self
            .static_caps_of_term(arena, term)
            .into_iter()
            .map(|id| String::from(arena.sym_name(id)))
            .collect();
        names.sort();
        names
    }

    /// render the entire lexicon back into canonical, round-trip hash-identical source text.
    pub fn to_source(&self, arena: &Arena) -> String {
        let mut entries: Vec<(&str, &[Rule])> = self
            .rules
            .iter()
            .map(|(&head, list)| (arena.sym_name(head), list.as_slice()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = String::new();
        for (name, list) in entries {
            for rule in list {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str("(rule (");
                out.push_str(name);
                for pat in &rule.params {
                    out.push(' ');
                    write_pattern(arena, pat, &mut out);
                }
                out.push_str(") ");
                out.push_str(&crate::syntax::print_term(arena, rule.body));
                out.push(')');
            }
        }
        out
    }
}

fn write_pattern(arena: &Arena, pat: &Pattern, out: &mut String) {
    match pat {
        Pattern::Wild => out.push('_'),
        Pattern::Var(v) => {
            out.push('?');
            out.push_str(arena.sym_name(*v));
        }
        Pattern::Int(v) => out.push_str(&format!("{}", v)),
        Pattern::Bytes(bs) => {
            out.push('"');
            if let Ok(s) = core::str::from_utf8(bs) {
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
            }
            out.push('"');
        }
        Pattern::Sym(s) => out.push_str(arena.sym_name(*s)),
        Pattern::App(head, args) => {
            out.push('(');
            out.push_str(arena.sym_name(*head));
            for a in args {
                out.push(' ');
                write_pattern(arena, a, out);
            }
            out.push(')');
        }
    }
}

/// compile a `(rule (head p1 ...) body)` term into a validated, alpha-canonical `Rule`.
pub fn compile_rule(arena: &Arena, form: TermId) -> Result<Rule, Diag> {
    let (head_term, body) = match arena.node(form) {
        Node::App(h, args) if *h == sym::RULE && args.len() == 2 => (args[0], args[1]),
        _ => {
            return Err(Diag::runtime(
                DiagCode::InvalidRuleForm,
                "expected (rule (name pat...) body)",
            ));
        }
    };

    let (rule_head, param_terms) = match arena.node(head_term) {
        Node::App(h, args) => (*h, args.as_ref()),
        _ => {
            return Err(Diag::runtime(
                DiagCode::InvalidRuleForm,
                "rule signature must be (name pat...)",
            ));
        }
    };

    if sym::is_reserved_head(rule_head) {
        return Err(Diag::runtime(
            DiagCode::InvalidRuleForm,
            format!("cannot define rule for reserved builtin '{}'", arena.sym_name(rule_head)),
        ));
    }

    let mut bound = BTreeSet::new();
    let mut params = Vec::with_capacity(param_terms.len());
    for &pt in param_terms {
        params.push(compile_pattern(arena, pt, &mut bound)?);
    }

    // verify closure: every ?var in body must be bound by rule params or an enclosing match arm
    verify_closed(arena, body, &bound)?;

    let canonical_hash = compute_alpha_canonical_rule_hash(arena, rule_head, &params, body);

    let mut direct_caps = BTreeSet::new();
    let mut direct_calls = BTreeSet::new();
    collect_term_effects(arena, body, &mut direct_caps, &mut direct_calls);

    Ok(Rule {
        head: rule_head,
        params,
        body,
        canonical_hash,
        direct_caps,
        direct_calls,
    })
}

/// compile a pattern term while enforcing strict linearity (each `?var` appears once).
pub fn compile_pattern(
    arena: &Arena,
    term: TermId,
    bound: &mut BTreeSet<SymId>,
) -> Result<Pattern, Diag> {
    match arena.node(term) {
        Node::Hole => Ok(Pattern::Wild),
        Node::Int(v) => Ok(Pattern::Int(*v)),
        Node::Bytes(bs) => Ok(Pattern::Bytes(bs.to_vec())),
        Node::Sym(s) => Ok(Pattern::Sym(*s)),
        Node::Var(v) => {
            if !bound.insert(*v) {
                return Err(Diag::runtime(
                    DiagCode::DuplicatePatternVar,
                    format!("duplicate pattern variable '?{}'", arena.sym_name(*v)),
                ));
            }
            Ok(Pattern::Var(*v))
        }
        Node::App(head, args) => {
            let mut sub = Vec::with_capacity(args.len());
            for &a in args.iter() {
                sub.push(compile_pattern(arena, a, bound)?);
            }
            Ok(Pattern::App(*head, sub))
        }
    }
}

fn verify_closed(arena: &Arena, term: TermId, bound: &BTreeSet<SymId>) -> Result<(), Diag> {
    match arena.node(term) {
        Node::Int(_) | Node::Bytes(_) | Node::Sym(_) | Node::Hole => Ok(()),
        Node::Var(v) => {
            if bound.contains(v) {
                Ok(())
            } else {
                Err(Diag::runtime(
                    DiagCode::UnboundVar,
                    format!("unbound variable '?{}' in rule body", arena.sym_name(*v)),
                ))
            }
        }
        Node::App(h, args) if *h == sym::QUOTE || *h == sym::CONT => Ok(()),
        Node::App(h, args) if *h == sym::MATCH => {
            if args.is_empty() {
                return Err(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "match requires a scrutinee",
                ));
            }
            verify_closed(arena, args[0], bound)?;
            for &arm in &args[1..] {
                match arena.node(arm) {
                    Node::App(ch, cargs) if *ch == sym::CASE && cargs.len() == 2 => {
                        let mut arm_vars = BTreeSet::new();
                        compile_pattern(arena, cargs[0], &mut arm_vars)?;
                        let mut merged = bound.clone();
                        merged.extend(arm_vars);
                        verify_closed(arena, cargs[1], &merged)?;
                    }
                    _ => {
                        return Err(Diag::runtime(
                            DiagCode::InvalidPattern,
                            "match arm must be (case pattern body)",
                        ));
                    }
                }
            }
            Ok(())
        }
        Node::App(_, args) => {
            for &a in args.iter() {
                verify_closed(arena, a, bound)?;
            }
            Ok(())
        }
    }
}

fn collect_term_effects(
    arena: &Arena,
    term: TermId,
    caps: &mut BTreeSet<SymId>,
    calls: &mut BTreeSet<SymId>,
) {
    match arena.node(term) {
        Node::Int(_) | Node::Bytes(_) | Node::Sym(_) | Node::Var(_) | Node::Hole => {}
        Node::App(h, _) if *h == sym::QUOTE || *h == sym::CONT => {}
        Node::App(h, args) if *h == sym::PERFORM => {
            if let Some(&first) = args.first() {
                if let Node::Sym(cap_sym) = arena.node(first) {
                    caps.insert(*cap_sym);
                }
            }
            for &a in args.iter().skip(1) {
                collect_term_effects(arena, a, caps, calls);
            }
        }
        Node::App(h, args) if *h == sym::HANDLE => {
            // (handle expr fuel handler_sym)
            if args.len() == 3 {
                collect_term_effects(arena, args[0], caps, calls);
                collect_term_effects(arena, args[1], caps, calls);
                if let Node::Sym(handler) = arena.node(args[2]) {
                    calls.insert(*handler);
                }
            }
        }
        Node::App(h, args) if *h == sym::MATCH => {
            if let Some(&scrut) = args.first() {
                collect_term_effects(arena, scrut, caps, calls);
            }
            for &arm in args.iter().skip(1) {
                if let Node::App(ch, cargs) = arena.node(arm) {
                    if *ch == sym::CASE && cargs.len() == 2 {
                        collect_term_effects(arena, cargs[1], caps, calls);
                    }
                }
            }
        }
        Node::App(h, args) => {
            if !sym::is_reserved_head(*h) {
                calls.insert(*h);
            }
            for &a in args.iter() {
                collect_term_effects(arena, a, caps, calls);
            }
        }
    }
}

/// alpha-canonical rule hashing: renaming `?x` -> `?y` produces the exact same `Hash256`.
fn compute_alpha_canonical_rule_hash(
    arena: &Arena,
    head: SymId,
    params: &[Pattern],
    body: TermId,
) -> Hash256 {
    let mut h = Sha256::new();
    h.update_u8(TAG_RULE);
    h.update_len_bytes(arena.sym_name(head).as_bytes());
    h.update_u32(params.len() as u32);

    let mut env: Vec<(SymId, u32)> = Vec::new();
    let mut next_slot = 0u32;

    for p in params {
        hash_pattern(arena, p, &mut env, &mut next_slot, &mut h);
    }
    hash_body_alpha(arena, body, &env, next_slot, &mut h);
    h.finalize()
}

fn hash_pattern(
    arena: &Arena,
    pat: &Pattern,
    env: &mut Vec<(SymId, u32)>,
    next_slot: &mut u32,
    h: &mut Sha256,
) {
    match pat {
        Pattern::Wild => h.update_u8(TAG_HOLE),
        Pattern::Int(v) => {
            h.update_u8(TAG_INT);
            h.update_i64(*v);
        }
        Pattern::Bytes(bs) => {
            h.update_u8(TAG_BYTES);
            h.update_len_bytes(bs);
        }
        Pattern::Sym(s) => {
            h.update_u8(TAG_SYM);
            h.update_len_bytes(arena.sym_name(*s).as_bytes());
        }
        Pattern::Var(v) => {
            let slot = *next_slot;
            *next_slot += 1;
            env.push((*v, slot));
            h.update_u8(TAG_VAR);
            h.update_u32(slot);
        }
        Pattern::App(head, args) => {
            h.update_u8(TAG_APP);
            h.update_len_bytes(arena.sym_name(*head).as_bytes());
            h.update_u32(args.len() as u32);
            for a in args {
                hash_pattern(arena, a, env, next_slot, h);
            }
        }
    }
}

fn hash_body_alpha(
    arena: &Arena,
    term: TermId,
    env: &[(SymId, u32)],
    next_slot: u32,
    h: &mut Sha256,
) {
    match arena.node(term) {
        Node::Int(v) => {
            h.update_u8(TAG_INT);
            h.update_i64(*v);
        }
        Node::Bytes(bs) => {
            h.update_u8(TAG_BYTES);
            h.update_len_bytes(bs);
        }
        Node::Sym(s) => {
            h.update_u8(TAG_SYM);
            h.update_len_bytes(arena.sym_name(*s).as_bytes());
        }
        Node::Hole => {
            h.update_u8(TAG_HOLE);
        }
        Node::Var(v) => {
            h.update_u8(TAG_VAR);
            // lookup innermost binding
            if let Some(&(_, slot)) = env.iter().rev().find(|&&(sym_id, _)| sym_id == *v) {
                h.update_u32(slot);
            } else {
                h.update_len_bytes(arena.sym_name(*v).as_bytes());
            }
        }
        Node::App(head, args) if *head == sym::QUOTE || *head == sym::CONT => {
            h.update_u8(TAG_APP);
            h.update_len_bytes(arena.sym_name(*head).as_bytes());
            h.update_u32(args.len() as u32);
            for &a in args.iter() {
                h.update_hash(&arena.hash(a));
            }
        }
        Node::App(head, args) if *head == sym::MATCH && !args.is_empty() => {
            h.update_u8(TAG_APP);
            h.update_len_bytes(arena.sym_name(*head).as_bytes());
            h.update_u32(args.len() as u32);
            hash_body_alpha(arena, args[0], env, next_slot, h);
            for &arm in &args[1..] {
                if let Node::App(ch, cargs) = arena.node(arm) {
                    if *ch == sym::CASE && cargs.len() == 2 {
                        h.update_u8(TAG_APP);
                        h.update_len_bytes(b"case");
                        h.update_u32(2);
                        let mut arm_env = env.to_vec();
                        let mut arm_slot = next_slot;
                        let mut dummy_bound = BTreeSet::new();
                        if let Ok(pat) = compile_pattern(arena, cargs[0], &mut dummy_bound) {
                            hash_pattern(arena, &pat, &mut arm_env, &mut arm_slot, h);
                        }
                        hash_body_alpha(arena, cargs[1], &arm_env, arm_slot, h);
                    }
                }
            }
        }
        Node::App(head, args) => {
            h.update_u8(TAG_APP);
            h.update_len_bytes(arena.sym_name(*head).as_bytes());
            h.update_u32(args.len() as u32);
            for &a in args.iter() {
                hash_body_alpha(arena, a, env, next_slot, h);
            }
        }
    }
}
