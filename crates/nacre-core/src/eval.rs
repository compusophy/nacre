//! deterministic small-step supercombinator reducer with algebraic effects (`perform`/`handle`)
//! and pure content-addressed residual continuations.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;

use crate::arena::{sym, Arena, Node, SymId, TermId};
use crate::diag::{Diag, DiagCode};
use crate::fuel::Fuel;
use crate::lexicon::{compile_pattern, Lexicon, Pattern};

pub const MAX_HANDLE_DEPTH: usize = 32;
pub const MAX_FRAME_DEPTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// pure normal form reached.
    Done(TermId),
    /// algebraic effect yielded along with exact content-addressed residual term (contains one `_` hole).
    Yield { effect: TermId, resume: TermId },
    /// fuel exhausted cleanly; `resume` is the exact remaining expression to continue later.
    Exhausted { resume: TermId },
    /// coded, spanned deterministic fault (never panics).
    Fault(Diag),
}

enum Frame {
    /// evaluating arguments of an application `(head done... [cur] rest...)`
    AppArgs {
        head: SymId,
        done: Vec<TermId>,
        rest: Vec<TermId>,
    },
    /// evaluating arguments of `(perform cap done... [cur] rest...)`
    PerformArgs {
        cap: SymId,
        done: Vec<TermId>,
        rest: Vec<TermId>,
    },
    /// evaluating condition of `(if [cur] then_b else_b)`
    IfCond {
        then_b: TermId,
        else_b: TermId,
    },
    /// evaluating scrutinee of `(match [cur] arms...)`
    MatchScrut {
        arms: Vec<TermId>,
    },
    /// evaluating fuel expression of `(handle expr [cur] handler)`
    HandleFuel {
        expr: TermId,
        handler: SymId,
    },
    /// evaluating continuation value of `(resume [cur] reply_expr)`
    ResumeCont {
        reply_expr: TermId,
    },
    /// evaluating reply value of `(resume cont_val [cur])`
    ResumeReply {
        cont_val: TermId,
    },
    /// evaluating argument of `(eval [cur])`
    EvalArg,
}

enum Control {
    Eval(TermId),
    Return(TermId),
}

/// evaluate `expr` deterministically under `lexicon` and `fuel`.
pub fn eval(arena: &mut Arena, lexicon: &Lexicon, expr: TermId, fuel: &mut Fuel) -> Outcome {
    eval_inner(arena, lexicon, expr, fuel, 0)
}

fn eval_inner(
    arena: &mut Arena,
    lexicon: &Lexicon,
    root_expr: TermId,
    fuel: &mut Fuel,
    handle_depth: usize,
) -> Outcome {
    let mut frames: Vec<Frame> = Vec::with_capacity(32);
    let mut ctrl = Control::Eval(root_expr);

    loop {
        match ctrl {
            Control::Eval(term) => {
                if !fuel.charge(1) {
                    let resume = match reify_frames(arena, &frames, term) {
                        Ok(r) => r,
                        Err(d) => return Outcome::Fault(d),
                    };
                    return Outcome::Exhausted { resume };
                }

                match arena.node(term).clone() {
                    Node::Int(_) | Node::Bytes(_) | Node::Sym(_) | Node::Hole => {
                        ctrl = Control::Return(term);
                    }
                    Node::Var(v) => {
                        return Outcome::Fault(Diag::runtime(
                            DiagCode::UnboundVar,
                            format!("unbound variable '?{}' at runtime", arena.sym_name(v)),
                        ));
                    }
                    Node::App(head, args) => {
                        if frames.len() >= MAX_FRAME_DEPTH {
                            return Outcome::Fault(Diag::runtime(
                                DiagCode::MaxEvalDepth,
                                "maximum evaluation frame depth exceeded",
                            ));
                        }
                        match head {
                            sym::QUOTE => {
                                if args.len() != 1 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "quote expects exactly 1 argument",
                                    ));
                                }
                                ctrl = Control::Return(args[0]);
                            }
                            sym::CONT => {
                                // continuations are first-class inert values until passed to `resume`
                                ctrl = Control::Return(term);
                            }
                            sym::IF => {
                                if args.len() != 3 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "if expects 3 arguments: (if cond then else)",
                                    ));
                                }
                                frames.push(Frame::IfCond {
                                    then_b: args[1],
                                    else_b: args[2],
                                });
                                ctrl = Control::Eval(args[0]);
                            }
                            sym::MATCH => {
                                if args.len() < 2 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "match expects scrutinee and at least 1 case",
                                    ));
                                }
                                frames.push(Frame::MatchScrut {
                                    arms: args[1..].to_vec(),
                                });
                                ctrl = Control::Eval(args[0]);
                            }
                            sym::PERFORM => {
                                if args.is_empty() {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "perform expects capability tag",
                                    ));
                                }
                                let cap_sym = match arena.node(args[0]) {
                                    Node::Sym(s) => *s,
                                    _ => {
                                        return Outcome::Fault(Diag::runtime(
                                            DiagCode::TypeMismatch,
                                            "perform capability tag must be a symbol",
                                        ));
                                    }
                                };
                                if args.len() == 1 {
                                    let effect = match alloc_app(arena, fuel, cap_sym, &[]) {
                                        Ok(Some(t)) => t,
                                        Ok(None) => {
                                            let resume = match reify_frames(arena, &frames, term) {
                                                Ok(r) => r,
                                                Err(d) => return Outcome::Fault(d),
                                            };
                                            return Outcome::Exhausted { resume };
                                        }
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                    let resume =
                                        match reify_frames(arena, &frames, arena.term_hole()) {
                                            Ok(r) => r,
                                            Err(d) => return Outcome::Fault(d),
                                        };
                                    return Outcome::Yield { effect, resume };
                                } else {
                                    frames.push(Frame::PerformArgs {
                                        cap: cap_sym,
                                        done: Vec::with_capacity(args.len() - 1),
                                        rest: args[2..].to_vec(),
                                    });
                                    ctrl = Control::Eval(args[1]);
                                }
                            }
                            sym::HANDLE => {
                                if args.len() != 3 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "handle expects 3 arguments: (handle expr fuel handler)",
                                    ));
                                }
                                let handler_sym = match arena.node(args[2]) {
                                    Node::Sym(s) => *s,
                                    _ => {
                                        return Outcome::Fault(Diag::runtime(
                                            DiagCode::TypeMismatch,
                                            "handle handler must be a rule symbol",
                                        ));
                                    }
                                };
                                frames.push(Frame::HandleFuel {
                                    expr: args[0],
                                    handler: handler_sym,
                                });
                                ctrl = Control::Eval(args[1]);
                            }
                            sym::RESUME => {
                                if args.len() != 2 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "resume expects 2 arguments: (resume cont reply)",
                                    ));
                                }
                                frames.push(Frame::ResumeCont {
                                    reply_expr: args[1],
                                });
                                ctrl = Control::Eval(args[0]);
                            }
                            sym::EVAL => {
                                if args.len() != 1 {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::ArityMismatch,
                                        "eval expects 1 argument",
                                    ));
                                }
                                frames.push(Frame::EvalArg);
                                ctrl = Control::Eval(args[0]);
                            }
                            _ => {
                                if args.is_empty() {
                                    match apply_call(arena, lexicon, fuel, head, &[]) {
                                        CallStep::Value(v) => ctrl = Control::Return(v),
                                        CallStep::TailEval(next) => ctrl = Control::Eval(next),
                                        CallStep::Exhausted => {
                                            let resume = match reify_frames(arena, &frames, term) {
                                                Ok(r) => r,
                                                Err(d) => return Outcome::Fault(d),
                                            };
                                            return Outcome::Exhausted { resume };
                                        }
                                        CallStep::Fault(d) => return Outcome::Fault(d),
                                    }
                                } else {
                                    frames.push(Frame::AppArgs {
                                        head,
                                        done: Vec::with_capacity(args.len()),
                                        rest: args[1..].to_vec(),
                                    });
                                    ctrl = Control::Eval(args[0]);
                                }
                            }
                        }
                    }
                }
            }

            Control::Return(val) => {
                let Some(frame) = frames.pop() else {
                    return Outcome::Done(val);
                };

                match frame {
                    Frame::AppArgs {
                        head,
                        mut done,
                        mut rest,
                    } => {
                        done.push(val);
                        if !rest.is_empty() {
                            let next_arg = rest.remove(0);
                            frames.push(Frame::AppArgs { head, done, rest });
                            ctrl = Control::Eval(next_arg);
                        } else {
                            match apply_call(arena, lexicon, fuel, head, &done) {
                                CallStep::Value(v) => ctrl = Control::Return(v),
                                CallStep::TailEval(next) => ctrl = Control::Eval(next),
                                CallStep::Exhausted => {
                                    let reified_call = match reify_app_values(arena, head, &done) {
                                        Ok(t) => t,
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                    let resume = match reify_frames(arena, &frames, reified_call) {
                                        Ok(r) => r,
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                    return Outcome::Exhausted { resume };
                                }
                                CallStep::Fault(d) => return Outcome::Fault(d),
                            }
                        }
                    }

                    Frame::PerformArgs {
                        cap,
                        mut done,
                        mut rest,
                    } => {
                        done.push(val);
                        if !rest.is_empty() {
                            let next_arg = rest.remove(0);
                            frames.push(Frame::PerformArgs { cap, done, rest });
                            ctrl = Control::Eval(next_arg);
                        } else {
                            let effect = match alloc_app(arena, fuel, cap, &done) {
                                Ok(Some(t)) => t,
                                Ok(None) => {
                                    let reified = match reify_perform_values(arena, cap, &done) {
                                        Ok(t) => t,
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                    let resume = match reify_frames(arena, &frames, reified) {
                                        Ok(r) => r,
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                    return Outcome::Exhausted { resume };
                                }
                                Err(d) => return Outcome::Fault(d),
                            };
                            let resume = match reify_frames(arena, &frames, arena.term_hole()) {
                                Ok(r) => r,
                                Err(d) => return Outcome::Fault(d),
                            };
                            return Outcome::Yield { effect, resume };
                        }
                    }

                    Frame::IfCond { then_b, else_b } => match arena.node(val) {
                        Node::Sym(sym::TRUE) => ctrl = Control::Eval(then_b),
                        Node::Sym(sym::FALSE) => ctrl = Control::Eval(else_b),
                        _ => {
                            return Outcome::Fault(Diag::runtime(
                                DiagCode::TypeMismatch,
                                "if condition must evaluate to true or false",
                            ));
                        }
                    },

                    Frame::MatchScrut { arms } => {
                        let mut matched_body = None;
                        for arm in arms {
                            let (pat_term, body_term) = match arena.node(arm) {
                                Node::App(h, cargs) if *h == sym::CASE && cargs.len() == 2 => {
                                    (cargs[0], cargs[1])
                                }
                                _ => {
                                    return Outcome::Fault(Diag::runtime(
                                        DiagCode::InvalidPattern,
                                        "match arm must be (case pattern body)",
                                    ));
                                }
                            };
                            let mut bound = BTreeSet::new();
                            let pat = match compile_pattern(arena, pat_term, &mut bound) {
                                Ok(p) => p,
                                Err(d) => return Outcome::Fault(d),
                            };
                            let mut env = BTreeMap::new();
                            if match_pattern(arena, &pat, val, &mut env) {
                                match substitute(arena, fuel, body_term, &env) {
                                    Ok(Some(inst)) => {
                                        matched_body = Some(inst);
                                        break;
                                    }
                                    Ok(None) => {
                                        let resume =
                                            match reify_frames(arena, &frames, body_term) {
                                                Ok(r) => r,
                                                Err(d) => return Outcome::Fault(d),
                                            };
                                        return Outcome::Exhausted { resume };
                                    }
                                    Err(d) => return Outcome::Fault(d),
                                }
                            }
                        }
                        match matched_body {
                            Some(next) => ctrl = Control::Eval(next),
                            None => {
                                return Outcome::Fault(Diag::runtime(
                                    DiagCode::NonExhaustiveMatch,
                                    "no match case matched value",
                                ));
                            }
                        }
                    }

                    Frame::HandleFuel { expr, handler } => {
                        if handle_depth >= MAX_HANDLE_DEPTH {
                            return Outcome::Fault(Diag::runtime(
                                DiagCode::MaxEvalDepth,
                                "maximum nested handle depth exceeded",
                            ));
                        }
                        let req_fuel = match arena.node(val) {
                            Node::Int(n) => *n,
                            _ => {
                                return Outcome::Fault(Diag::runtime(
                                    DiagCode::TypeMismatch,
                                    "handle fuel budget must be an integer",
                                ));
                            }
                        };
                        let mut child_fuel = match fuel.slice_child(req_fuel) {
                            Ok(f) => f,
                            Err(d) => return Outcome::Fault(d),
                        };
                        let child_outcome =
                            eval_inner(arena, lexicon, expr, &mut child_fuel, handle_depth + 1);
                        fuel.settle_child(child_fuel.used());

                        match child_outcome {
                            Outcome::Done(child_val) => {
                                match alloc_app(arena, fuel, sym::OK, &[child_val]) {
                                    Ok(Some(wrapped)) => ctrl = Control::Return(wrapped),
                                    Ok(None) => {
                                        let wrapped = match arena.mk_app(sym::OK, &[child_val]) {
                                            Ok((t, _)) => t,
                                            Err(d) => return Outcome::Fault(d),
                                        };
                                        let resume = match reify_frames(arena, &frames, wrapped) {
                                            Ok(r) => r,
                                            Err(d) => return Outcome::Fault(d),
                                        };
                                        return Outcome::Exhausted { resume };
                                    }
                                    Err(d) => return Outcome::Fault(d),
                                }
                            }
                            Outcome::Yield { effect, resume } => {
                                let cont = match arena.mk_app(sym::CONT, &[resume]) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let eff_protected = match protect_value(arena, effect) {
                                    Ok(t) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let call = match arena.mk_app(handler, &[eff_protected, cont]) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                ctrl = Control::Eval(call);
                            }
                            Outcome::Exhausted { resume } => {
                                let tag = match arena.mk_app(sym::EXHAUSTED, &[]) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let cont = match arena.mk_app(sym::CONT, &[resume]) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let tag_protected = match protect_value(arena, tag) {
                                    Ok(t) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let call = match arena.mk_app(handler, &[tag_protected, cont]) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                ctrl = Control::Eval(call);
                            }
                            Outcome::Fault(diag) => {
                                let code_term = match arena.mk_str(diag.code.as_str()) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let msg_term = match arena.mk_str(&diag.message) {
                                    Ok((t, _)) => t,
                                    Err(d) => return Outcome::Fault(d),
                                };
                                let fault_val =
                                    match arena.mk_app(sym::FAULT, &[code_term, msg_term]) {
                                        Ok((t, _)) => t,
                                        Err(d) => return Outcome::Fault(d),
                                    };
                                ctrl = Control::Return(fault_val);
                            }
                        }
                    }

                    Frame::ResumeCont { reply_expr } => {
                        frames.push(Frame::ResumeReply { cont_val: val });
                        ctrl = Control::Eval(reply_expr);
                    }

                    Frame::ResumeReply { cont_val } => {
                        let body = match arena.node(cont_val) {
                            Node::App(h, cargs) if *h == sym::CONT && cargs.len() == 1 => cargs[0],
                            _ => {
                                return Outcome::Fault(Diag::runtime(
                                    DiagCode::InvalidResume,
                                    "resume expects a continuation value (cont ...)",
                                ));
                            }
                        };
                        match plug_hole(arena, body, val) {
                            Ok(resumed_expr) => ctrl = Control::Eval(resumed_expr),
                            Err(d) => return Outcome::Fault(d),
                        }
                    }

                    Frame::EvalArg => {
                        ctrl = Control::Eval(val);
                    }
                }
            }
        }
    }
}

/// plug a reply value into the single active `_` hole of a residual continuation term.
/// wraps compound/symbol replies in `(quote ...)` so untrusted external replies can never
/// accidentally execute as code (injection-proof by construction).
pub fn plug_hole(arena: &mut Arena, residual: TermId, reply: TermId) -> Result<TermId, Diag> {
    let protected = protect_value(arena, reply)?;
    let (res, _) = plug_hole_inner(arena, residual, protected)?;
    Ok(res)
}

fn plug_hole_inner(
    arena: &mut Arena,
    term: TermId,
    replacement: TermId,
) -> Result<(TermId, bool), Diag> {
    match arena.node(term).clone() {
        Node::Hole => Ok((replacement, true)),
        Node::Int(_) | Node::Bytes(_) | Node::Sym(_) | Node::Var(_) => Ok((term, false)),
        // never descend into quoted data or nested continuations
        Node::App(h, _) if h == sym::QUOTE || h == sym::CONT => Ok((term, false)),
        Node::App(head, args) => {
            let mut changed = false;
            let mut new_args = Vec::with_capacity(args.len());
            for &a in args.iter() {
                if !changed {
                    let (na, plugged) = plug_hole_inner(arena, a, replacement)?;
                    if plugged {
                        changed = true;
                    }
                    new_args.push(na);
                } else {
                    new_args.push(a);
                }
            }
            if changed {
                Ok((arena.mk_app(head, &new_args)?.0, true))
            } else {
                Ok((term, false))
            }
        }
    }
}

/// protect an already-evaluated value so re-evaluating it returns the exact value untouched.
pub fn protect_value(arena: &mut Arena, val: TermId) -> Result<TermId, Diag> {
    match arena.node(val) {
        Node::Int(_) | Node::Bytes(_) => Ok(val),
        Node::Sym(s) if matches!(*s, sym::TRUE | sym::FALSE | sym::NIL) => Ok(val),
        Node::App(h, _) if *h == sym::CONT => Ok(val),
        _ => Ok(arena.mk_app(sym::QUOTE, &[val])?.0),
    }
}

fn reify_frames(arena: &mut Arena, frames: &[Frame], mut cur: TermId) -> Result<TermId, Diag> {
    for frame in frames.iter().rev() {
        cur = match frame {
            Frame::AppArgs { head, done, rest } => {
                let mut args = Vec::with_capacity(done.len() + 1 + rest.len());
                for &v in done {
                    args.push(protect_value(arena, v)?);
                }
                args.push(cur);
                args.extend_from_slice(rest);
                arena.mk_app(*head, &args)?.0
            }
            Frame::PerformArgs { cap, done, rest } => {
                let mut args = Vec::with_capacity(1 + done.len() + 1 + rest.len());
                args.push(arena.mk_sym(*cap)?.0);
                for &v in done {
                    args.push(protect_value(arena, v)?);
                }
                args.push(cur);
                args.extend_from_slice(rest);
                arena.mk_app(sym::PERFORM, &args)?.0
            }
            Frame::IfCond { then_b, else_b } => arena.mk_app(sym::IF, &[cur, *then_b, *else_b])?.0,
            Frame::MatchScrut { arms } => {
                let mut args = Vec::with_capacity(1 + arms.len());
                args.push(cur);
                args.extend_from_slice(arms);
                arena.mk_app(sym::MATCH, &args)?.0
            }
            Frame::HandleFuel { expr, handler } => {
                let hsym = arena.mk_sym(*handler)?.0;
                arena.mk_app(sym::HANDLE, &[*expr, cur, hsym])?.0
            }
            Frame::ResumeCont { reply_expr } => {
                arena.mk_app(sym::RESUME, &[cur, *reply_expr])?.0
            }
            Frame::ResumeReply { cont_val } => {
                arena.mk_app(sym::RESUME, &[*cont_val, cur])?.0
            }
            Frame::EvalArg => arena.mk_app(sym::EVAL, &[cur])?.0,
        };
    }
    Ok(cur)
}

fn reify_app_values(arena: &mut Arena, head: SymId, vals: &[TermId]) -> Result<TermId, Diag> {
    let mut args = Vec::with_capacity(vals.len());
    for &v in vals {
        args.push(protect_value(arena, v)?);
    }
    Ok(arena.mk_app(head, &args)?.0)
}

fn reify_perform_values(arena: &mut Arena, cap: SymId, vals: &[TermId]) -> Result<TermId, Diag> {
    let mut args = Vec::with_capacity(1 + vals.len());
    args.push(arena.mk_sym(cap)?.0);
    for &v in vals {
        args.push(protect_value(arena, v)?);
    }
    Ok(arena.mk_app(sym::PERFORM, &args)?.0)
}

enum CallStep {
    Value(TermId),
    TailEval(TermId),
    Exhausted,
    Fault(Diag),
}

fn apply_call(
    arena: &mut Arena,
    lexicon: &Lexicon,
    fuel: &mut Fuel,
    head: SymId,
    args: &[TermId],
) -> CallStep {
    // 1. builtins
    if let Some(step) = apply_builtin(arena, fuel, head, args) {
        return step;
    }

    // 2. lexicon supercombinator rules (linear pattern match in order)
    if let Some(rules) = lexicon.rules_for(head) {
        for rule in rules {
            if rule.params.len() != args.len() {
                continue;
            }
            let mut env = BTreeMap::new();
            let mut matched = true;
            for (pat, &arg) in rule.params.iter().zip(args.iter()) {
                if !match_pattern(arena, pat, arg, &mut env) {
                    matched = false;
                    break;
                }
            }
            if matched {
                return match substitute(arena, fuel, rule.body, &env) {
                    Ok(Some(inst)) => CallStep::TailEval(inst),
                    Ok(None) => CallStep::Exhausted,
                    Err(d) => CallStep::Fault(d),
                };
            }
        }
    }

    // 3. inert data constructor (mathematica / algebraic term normal form)
    match alloc_app(arena, fuel, head, args) {
        Ok(Some(t)) => CallStep::Value(t),
        Ok(None) => CallStep::Exhausted,
        Err(d) => CallStep::Fault(d),
    }
}

fn apply_builtin(
    arena: &mut Arena,
    fuel: &mut Fuel,
    head: SymId,
    args: &[TermId],
) -> Option<CallStep> {
    let step = match head {
        sym::ADD => bin_int_op(arena, fuel, args, "add", |a, b| a.checked_add(b)),
        sym::SUB => bin_int_op(arena, fuel, args, "sub", |a, b| a.checked_sub(b)),
        sym::MUL => bin_int_op(arena, fuel, args, "mul", |a, b| a.checked_mul(b)),
        sym::DIV => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(DiagCode::ArityMismatch, "div expects 2 args"))
            } else {
                match (arena.node(args[0]), arena.node(args[1])) {
                    (Node::Int(_), Node::Int(0)) => {
                        CallStep::Fault(Diag::runtime(DiagCode::DivisionByZero, "division by zero"))
                    }
                    (Node::Int(a), Node::Int(b)) => match a.checked_div(*b) {
                        Some(v) => alloc_int_step(arena, fuel, v),
                        None => CallStep::Fault(Diag::runtime(
                            DiagCode::IntOverflow,
                            "integer overflow in div",
                        )),
                    },
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "div expects integer arguments",
                    )),
                }
            }
        }
        sym::MOD => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(DiagCode::ArityMismatch, "mod expects 2 args"))
            } else {
                match (arena.node(args[0]), arena.node(args[1])) {
                    (Node::Int(_), Node::Int(0)) => {
                        CallStep::Fault(Diag::runtime(DiagCode::DivisionByZero, "modulo by zero"))
                    }
                    (Node::Int(a), Node::Int(b)) => match a.checked_rem(*b) {
                        Some(v) => alloc_int_step(arena, fuel, v),
                        None => CallStep::Fault(Diag::runtime(
                            DiagCode::IntOverflow,
                            "integer overflow in mod",
                        )),
                    },
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "mod expects integer arguments",
                    )),
                }
            }
        }
        sym::NEG => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(DiagCode::ArityMismatch, "neg expects 1 arg"))
            } else if let Node::Int(a) = arena.node(args[0]) {
                match a.checked_neg() {
                    Some(v) => alloc_int_step(arena, fuel, v),
                    None => {
                        CallStep::Fault(Diag::runtime(DiagCode::IntOverflow, "overflow in neg"))
                    }
                }
            } else {
                CallStep::Fault(Diag::runtime(
                    DiagCode::TypeMismatch,
                    "neg expects an integer",
                ))
            }
        }
        sym::EQ => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(DiagCode::ArityMismatch, "eq expects 2 args"))
            } else {
                // o(1) structural merkle-dag equality!
                CallStep::Value(arena.term_bool(args[0] == args[1]))
            }
        }
        sym::LT => cmp_int_op(arena, args, "lt", |a, b| a < b),
        sym::LE => cmp_int_op(arena, args, "le", |a, b| a <= b),
        sym::GT => cmp_int_op(arena, args, "gt", |a, b| a > b),
        sym::GE => cmp_int_op(arena, args, "ge", |a, b| a >= b),
        sym::NOT => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(DiagCode::ArityMismatch, "not expects 1 arg"))
            } else {
                match arena.node(args[0]) {
                    Node::Sym(sym::TRUE) => CallStep::Value(arena.term_false()),
                    Node::Sym(sym::FALSE) => CallStep::Value(arena.term_true()),
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "not expects a boolean",
                    )),
                }
            }
        }
        sym::AND => bool_bin_op(arena, args, "and", |a, b| a && b),
        sym::OR => bool_bin_op(arena, args, "or", |a, b| a || b),
        sym::LIST => {
            let mut acc = arena.term_nil();
            for &item in args.iter().rev() {
                match alloc_app(arena, fuel, sym::CONS, &[item, acc]) {
                    Ok(Some(next)) => acc = next,
                    Ok(None) => return Some(CallStep::Exhausted),
                    Err(d) => return Some(CallStep::Fault(d)),
                }
            }
            CallStep::Value(acc)
        }
        sym::STR_LEN => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "str_len expects 1 arg",
                ))
            } else if let Node::Bytes(bs) = arena.node(args[0]) {
                let len = bs.len() as i64;
                alloc_int_step(arena, fuel, len)
            } else {
                CallStep::Fault(Diag::runtime(
                    DiagCode::TypeMismatch,
                    "str_len expects bytes/string",
                ))
            }
        }
        sym::STR_CAT => {
            let mut buf = Vec::new();
            for &a in args {
                match arena.node(a) {
                    Node::Bytes(bs) => buf.extend_from_slice(bs),
                    _ => {
                        return Some(CallStep::Fault(Diag::runtime(
                            DiagCode::TypeMismatch,
                            "str_cat expects bytes/string arguments",
                        )));
                    }
                }
            }
            alloc_bytes_step(arena, fuel, &buf)
        }
        sym::STR_SLICE => {
            if args.len() != 3 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "str_slice expects 3 args: (str_slice s start end)",
                ))
            } else {
                match (arena.node(args[0]), arena.node(args[1]), arena.node(args[2])) {
                    (Node::Bytes(bs), Node::Int(s), Node::Int(e)) => {
                        let start = (*s).max(0) as usize;
                        let end = (*e).max(0) as usize;
                        let s_clamped = start.min(bs.len());
                        let e_clamped = end.min(bs.len()).max(s_clamped);
                        let slice = bs[s_clamped..e_clamped].to_vec();
                        alloc_bytes_step(arena, fuel, &slice)
                    }
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "str_slice expects (bytes, int, int)",
                    )),
                }
            }
        }
        sym::STR_CONTAINS => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "str_contains expects 2 args",
                ))
            } else {
                match (arena.node(args[0]), arena.node(args[1])) {
                    (Node::Bytes(hay), Node::Bytes(needle)) => {
                        let found = if needle.is_empty() {
                            true
                        } else {
                            hay.windows(needle.len()).any(|w| w == needle.as_ref())
                        };
                        CallStep::Value(arena.term_bool(found))
                    }
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "str_contains expects 2 strings",
                    )),
                }
            }
        }
        sym::STR_STARTS_WITH => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "str_starts_with expects 2 args",
                ))
            } else {
                match (arena.node(args[0]), arena.node(args[1])) {
                    (Node::Bytes(hay), Node::Bytes(prefix)) => {
                        CallStep::Value(arena.term_bool(hay.starts_with(prefix)))
                    }
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "str_starts_with expects 2 strings",
                    )),
                }
            }
        }
        sym::INT_TO_STR => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "int_to_str expects 1 arg",
                ))
            } else if let Node::Int(v) = arena.node(args[0]) {
                let s = format!("{}", v);
                alloc_bytes_step(arena, fuel, s.as_bytes())
            } else {
                CallStep::Fault(Diag::runtime(
                    DiagCode::TypeMismatch,
                    "int_to_str expects an integer",
                ))
            }
        }
        sym::STR_TO_INT => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "str_to_int expects 1 arg",
                ))
            } else if let Node::Bytes(bs) = arena.node(args[0]) {
                let parsed = core::str::from_utf8(bs).ok().and_then(|s| s.parse::<i64>().ok());
                match parsed {
                    Some(v) => match alloc_int(arena, fuel, v) {
                        Ok(Some(iv)) => match alloc_app(arena, fuel, sym::OK, &[iv]) {
                            Ok(Some(t)) => CallStep::Value(t),
                            Ok(None) => CallStep::Exhausted,
                            Err(d) => CallStep::Fault(d),
                        },
                        Ok(None) => CallStep::Exhausted,
                        Err(d) => CallStep::Fault(d),
                    },
                    None => match alloc_bytes(arena, fuel, b"invalid_int") {
                        Ok(Some(msg)) => match alloc_app(arena, fuel, sym::ERR, &[msg]) {
                            Ok(Some(t)) => CallStep::Value(t),
                            Ok(None) => CallStep::Exhausted,
                            Err(d) => CallStep::Fault(d),
                        },
                        Ok(None) => CallStep::Exhausted,
                        Err(d) => CallStep::Fault(d),
                    },
                }
            } else {
                CallStep::Fault(Diag::runtime(
                    DiagCode::TypeMismatch,
                    "str_to_int expects a string",
                ))
            }
        }
        sym::TERM_HASH => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "term_hash expects 1 arg",
                ))
            } else {
                let hex = arena.hash(args[0]).to_hex();
                alloc_bytes_step(arena, fuel, hex.as_bytes())
            }
        }
        sym::TERM_TAG => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "term_tag expects 1 arg",
                ))
            } else {
                let tag_name = match arena.node(args[0]) {
                    Node::Int(_) => "int",
                    Node::Bytes(_) => "bytes",
                    Node::Sym(_) => "sym",
                    Node::Var(_) => "var",
                    Node::Hole => "hole",
                    Node::App(h, _) => {
                        let s = *h;
                        return Some(match alloc_sym(arena, fuel, s) {
                            Ok(Some(t)) => CallStep::Value(t),
                            Ok(None) => CallStep::Exhausted,
                            Err(d) => CallStep::Fault(d),
                        });
                    }
                };
                let s = arena.intern_sym(tag_name);
                match alloc_sym(arena, fuel, s) {
                    Ok(Some(t)) => CallStep::Value(t),
                    Ok(None) => CallStep::Exhausted,
                    Err(d) => CallStep::Fault(d),
                }
            }
        }
        sym::TERM_ARITY => {
            if args.len() != 1 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "term_arity expects 1 arg",
                ))
            } else {
                let arity = match arena.node(args[0]) {
                    Node::App(_, a) => a.len() as i64,
                    _ => 0,
                };
                alloc_int_step(arena, fuel, arity)
            }
        }
        sym::TERM_ARG => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "term_arg expects 2 args: (term_arg term idx)",
                ))
            } else {
                match (arena.node(args[0]), arena.node(args[1])) {
                    (Node::App(_, a), Node::Int(idx)) => {
                        if *idx >= 0 && (*idx as usize) < a.len() {
                            CallStep::Value(a[*idx as usize])
                        } else {
                            CallStep::Fault(Diag::runtime(
                                DiagCode::TypeMismatch,
                                "term_arg index out of bounds",
                            ))
                        }
                    }
                    _ => CallStep::Fault(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "term_arg expects (app_term, int)",
                    )),
                }
            }
        }
        sym::TERM_MAKE => {
            if args.len() != 2 {
                CallStep::Fault(Diag::runtime(
                    DiagCode::ArityMismatch,
                    "term_make expects 2 args: (term_make head args_list)",
                ))
            } else {
                let head_sym = match arena.node(args[0]) {
                    Node::Sym(s) => *s,
                    _ => {
                        return Some(CallStep::Fault(Diag::runtime(
                            DiagCode::TypeMismatch,
                            "term_make head must be a symbol",
                        )));
                    }
                };
                let mut list_items = Vec::new();
                let mut cur = args[1];
                loop {
                    match arena.node(cur) {
                        Node::Sym(sym::NIL) => break,
                        Node::App(h, cargs) if *h == sym::CONS && cargs.len() == 2 => {
                            list_items.push(cargs[0]);
                            cur = cargs[1];
                        }
                        _ => {
                            return Some(CallStep::Fault(Diag::runtime(
                                DiagCode::TypeMismatch,
                                "term_make second arg must be a cons/nil list",
                            )));
                        }
                    }
                }
                match alloc_app(arena, fuel, head_sym, &list_items) {
                    Ok(Some(t)) => CallStep::Value(t),
                    Ok(None) => CallStep::Exhausted,
                    Err(d) => CallStep::Fault(d),
                }
            }
        }
        _ => return None,
    };
    Some(step)
}

fn bin_int_op(
    arena: &mut Arena,
    fuel: &mut Fuel,
    args: &[TermId],
    name: &str,
    op: impl FnOnce(i64, i64) -> Option<i64>,
) -> CallStep {
    if args.len() != 2 {
        return CallStep::Fault(Diag::runtime(
            DiagCode::ArityMismatch,
            format!("{} expects 2 args", name),
        ));
    }
    match (arena.node(args[0]), arena.node(args[1])) {
        (Node::Int(a), Node::Int(b)) => match op(*a, *b) {
            Some(v) => alloc_int_step(arena, fuel, v),
            None => CallStep::Fault(Diag::runtime(
                DiagCode::IntOverflow,
                format!("integer overflow in {}", name),
            )),
        },
        _ => CallStep::Fault(Diag::runtime(
            DiagCode::TypeMismatch,
            format!("{} expects integer arguments", name),
        )),
    }
}

fn cmp_int_op(
    arena: &Arena,
    args: &[TermId],
    name: &str,
    op: impl FnOnce(i64, i64) -> bool,
) -> CallStep {
    if args.len() != 2 {
        return CallStep::Fault(Diag::runtime(
            DiagCode::ArityMismatch,
            format!("{} expects 2 args", name),
        ));
    }
    match (arena.node(args[0]), arena.node(args[1])) {
        (Node::Int(a), Node::Int(b)) => CallStep::Value(arena.term_bool(op(*a, *b))),
        _ => CallStep::Fault(Diag::runtime(
            DiagCode::TypeMismatch,
            format!("{} expects integer arguments", name),
        )),
    }
}

fn bool_bin_op(
    arena: &Arena,
    args: &[TermId],
    name: &str,
    op: impl FnOnce(bool, bool) -> bool,
) -> CallStep {
    if args.len() != 2 {
        return CallStep::Fault(Diag::runtime(
            DiagCode::ArityMismatch,
            format!("{} expects 2 args", name),
        ));
    }
    let a = match arena.node(args[0]) {
        Node::Sym(sym::TRUE) => true,
        Node::Sym(sym::FALSE) => false,
        _ => {
            return CallStep::Fault(Diag::runtime(
                DiagCode::TypeMismatch,
                format!("{} expects boolean arguments", name),
            ));
        }
    };
    let b = match arena.node(args[1]) {
        Node::Sym(sym::TRUE) => true,
        Node::Sym(sym::FALSE) => false,
        _ => {
            return CallStep::Fault(Diag::runtime(
                DiagCode::TypeMismatch,
                format!("{} expects boolean arguments", name),
            ));
        }
    };
    CallStep::Value(arena.term_bool(op(a, b)))
}

fn alloc_int(arena: &mut Arena, fuel: &mut Fuel, v: i64) -> Result<Option<TermId>, Diag> {
    if !fuel.charge(1) {
        return Ok(None);
    }
    let (id, _) = arena.mk_int(v)?;
    Ok(Some(id))
}

fn alloc_int_step(arena: &mut Arena, fuel: &mut Fuel, v: i64) -> CallStep {
    match alloc_int(arena, fuel, v) {
        Ok(Some(t)) => CallStep::Value(t),
        Ok(None) => CallStep::Exhausted,
        Err(d) => CallStep::Fault(d),
    }
}

fn alloc_bytes(arena: &mut Arena, fuel: &mut Fuel, bs: &[u8]) -> Result<Option<TermId>, Diag> {
    if !fuel.charge(1) {
        return Ok(None);
    }
    let (id, _) = arena.mk_bytes(bs)?;
    Ok(Some(id))
}

fn alloc_bytes_step(arena: &mut Arena, fuel: &mut Fuel, bs: &[u8]) -> CallStep {
    match alloc_bytes(arena, fuel, bs) {
        Ok(Some(t)) => CallStep::Value(t),
        Ok(None) => CallStep::Exhausted,
        Err(d) => CallStep::Fault(d),
    }
}

fn alloc_sym(arena: &mut Arena, fuel: &mut Fuel, s: SymId) -> Result<Option<TermId>, Diag> {
    if !fuel.charge(1) {
        return Ok(None);
    }
    let (id, _) = arena.mk_sym(s)?;
    Ok(Some(id))
}

fn alloc_app(
    arena: &mut Arena,
    fuel: &mut Fuel,
    head: SymId,
    args: &[TermId],
) -> Result<Option<TermId>, Diag> {
    if !fuel.charge(1) {
        return Ok(None);
    }
    let (id, _) = arena.mk_app(head, args)?;
    Ok(Some(id))
}

fn match_pattern(
    arena: &Arena,
    pat: &Pattern,
    val: TermId,
    env: &mut BTreeMap<SymId, TermId>,
) -> bool {
    match pat {
        Pattern::Wild => true,
        Pattern::Var(v) => {
            env.insert(*v, val);
            true
        }
        Pattern::Int(expected) => matches!(arena.node(val), Node::Int(v) if *v == *expected),
        Pattern::Bytes(expected) => {
            matches!(arena.node(val), Node::Bytes(bs) if bs.as_ref() == expected.as_slice())
        }
        Pattern::Sym(expected) => matches!(arena.node(val), Node::Sym(s) if *s == *expected),
        Pattern::App(head, sub_pats) => match arena.node(val) {
            Node::App(val_head, val_args)
                if *val_head == *head && val_args.len() == sub_pats.len() =>
            {
                for (sp, &va) in sub_pats.iter().zip(val_args.iter()) {
                    if !match_pattern(arena, sp, va, env) {
                        return false;
                    }
                }
                true
            }
            _ => false,
        },
    }
}

/// capture-free substitution of closed values into a rule/match body.
/// protects substituted `App`/`Sym` values with `(quote ...)` so closed data is never re-executed.
fn substitute(
    arena: &mut Arena,
    fuel: &mut Fuel,
    term: TermId,
    env: &BTreeMap<SymId, TermId>,
) -> Result<Option<TermId>, Diag> {
    if env.is_empty() {
        return Ok(Some(term));
    }
    let mut memo: BTreeMap<TermId, TermId> = BTreeMap::new();
    subst_inner(arena, fuel, term, env, &mut memo)
}

fn subst_inner(
    arena: &mut Arena,
    fuel: &mut Fuel,
    term: TermId,
    env: &BTreeMap<SymId, TermId>,
    memo: &mut BTreeMap<TermId, TermId>,
) -> Result<Option<TermId>, Diag> {
    if let Some(&cached) = memo.get(&term) {
        return Ok(Some(cached));
    }
    let res = match arena.node(term).clone() {
        Node::Int(_) | Node::Bytes(_) | Node::Sym(_) | Node::Hole => term,
        Node::Var(v) => match env.get(&v) {
            Some(&val) => {
                let protected = protect_value(arena, val)?;
                protected
            }
            None => term,
        },
        Node::App(h, _) if h == sym::QUOTE || h == sym::CONT => term,
        Node::App(h, args) if h == sym::MATCH && !args.is_empty() => {
            let Some(new_scrut) = subst_inner(arena, fuel, args[0], env, memo)? else {
                return Ok(None);
            };
            let mut new_args = Vec::with_capacity(args.len());
            new_args.push(new_scrut);
            for &arm in &args[1..] {
                match arena.node(arm).clone() {
                    Node::App(ch, cargs) if ch == sym::CASE && cargs.len() == 2 => {
                        let mut shadowed = BTreeSet::new();
                        let _ = compile_pattern(arena, cargs[0], &mut shadowed);
                        let mut arm_env = env.clone();
                        for s in shadowed {
                            arm_env.remove(&s);
                        }
                        let Some(new_body) = substitute(arena, fuel, cargs[1], &arm_env)? else {
                            return Ok(None);
                        };
                        let Some(new_arm) = alloc_app(arena, fuel, sym::CASE, &[cargs[0], new_body])?
                        else {
                            return Ok(None);
                        };
                        new_args.push(new_arm);
                    }
                    _ => new_args.push(arm),
                }
            }
            let Some(new_match) = alloc_app(arena, fuel, sym::MATCH, &new_args)? else {
                return Ok(None);
            };
            new_match
        }
        Node::App(head, args) => {
            let mut new_args = Vec::with_capacity(args.len());
            let mut changed = false;
            for &a in args.iter() {
                let Some(na) = subst_inner(arena, fuel, a, env, memo)? else {
                    return Ok(None);
                };
                if na != a {
                    changed = true;
                }
                new_args.push(na);
            }
            if changed {
                let Some(new_app) = alloc_app(arena, fuel, head, &new_args)? else {
                    return Ok(None);
                };
                new_app
            } else {
                term
            }
        }
    };
    memo.insert(term, res);
    Ok(Some(res))
}
