//! tier-2 pure wasm reflex compiler (`modlite`-style zero-dep wasm 1.0 binary emitter)
//! plus a deterministic pure-rust mvp wasm differential-oracle executor.
//!
//! compiles pure (`caps == []`), closed `i64` supercombinators into standalone,
//! trap-free, fuel-metered `.wasm` modules keyed by the symbolic rule's canonical hash.
//! the symbolic rule remains the canonical identity; wasm is strictly a verified L1 reflex.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::arena::{sym, Arena, Node, SymId, TermId};
use crate::diag::{Diag, DiagCode};
use crate::hash::{sha256, Hash256};
use crate::lexicon::{Lexicon, Pattern, Rule};

/// compiled tier-2 wasm reflex linked back to its symbolic rule identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmReflex {
    pub entry_name: String,
    pub arity: u32,
    pub lexicon_hash: Hash256,
    pub rule_hash: Hash256,
    pub wasm_bytes: Vec<u8>,
    pub wasm_hash: Hash256,
}

/// status codes returned via wasm global `$status` (never traps the host!).
pub const WASM_STATUS_OK: i32 = 0;
pub const WASM_STATUS_EXHAUSTED: i32 = 1;
pub const WASM_STATUS_DIV_ZERO: i32 = 2;

/// result of executing a compiled wasm reflex in the built-in differential oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasmExecResult {
    pub status: i32,
    pub value: i64,
    pub fuel_used: u64,
}

// wasm 1.0 section ids
const SEC_TYPE: u8 = 1;
const SEC_FUNCTION: u8 = 3;
const SEC_GLOBAL: u8 = 6;
const SEC_EXPORT: u8 = 7;
const SEC_CODE: u8 = 10;

// wasm 1.0 value types
const VAL_I32: u8 = 0x7f;
const VAL_I64: u8 = 0x7e;

// wasm 1.0 opcodes
const OP_BLOCK: u8 = 0x02;
const OP_IF: u8 = 0x04;
const OP_ELSE: u8 = 0x05;
const OP_END: u8 = 0x0b;
const OP_BR: u8 = 0x0c;
const OP_BR_IF: u8 = 0x0d;
const OP_RETURN: u8 = 0x0f;
const OP_CALL: u8 = 0x10;
const OP_DROP: u8 = 0x1a;
const OP_LOCAL_GET: u8 = 0x20;
const OP_LOCAL_SET: u8 = 0x21;
const OP_LOCAL_TEE: u8 = 0x22;
const OP_GLOBAL_GET: u8 = 0x23;
const OP_GLOBAL_SET: u8 = 0x24;
const OP_I32_CONST: u8 = 0x41;
const OP_I64_CONST: u8 = 0x42;
const OP_I32_EQZ: u8 = 0x45;
const OP_I32_NE: u8 = 0x47;
const OP_I32_AND: u8 = 0x71;
const OP_I32_OR: u8 = 0x72;
const OP_I64_EQZ: u8 = 0x50;
const OP_I64_EQ: u8 = 0x51;
const OP_I64_LT_S: u8 = 0x53;
const OP_I64_GT_S: u8 = 0x55;
const OP_I64_LE_S: u8 = 0x57;
const OP_I64_GE_S: u8 = 0x59;
const OP_I64_ADD: u8 = 0x7c;
const OP_I64_SUB: u8 = 0x7d;
const OP_I64_MUL: u8 = 0x7e;
const OP_I64_DIV_S: u8 = 0x7f;
const OP_I64_REM_S: u8 = 0x81;

const GLOBAL_FUEL: u32 = 0;
const GLOBAL_STATUS: u32 = 1;

/// compile a pure `i64` rule (and any pure `i64` helpers it calls in `lexicon`)
/// into a standalone, fuel-metered, trap-free WebAssembly 1.0 binary module.
///
/// exports:
///   - `run(p0: i64, ..., fuel_limit: i64) -> i64`
///   - `get_status() -> i32` (`0=ok`, `1=exhausted`, `2=div0`)
///   - `get_fuel_rem() -> i64`
pub fn compile_pure_i64_reflex(
    arena: &Arena,
    lexicon: &Lexicon,
    entry_head: SymId,
) -> Result<WasmReflex, Diag> {
    let entry_clauses = lexicon.rules_for(entry_head).ok_or_else(|| {
        Diag::runtime(
            DiagCode::InvalidRuleForm,
            format!("no rule named '{}' in lexicon", arena.sym_name(entry_head)),
        )
    })?;
    if entry_clauses.is_empty() {
        return Err(Diag::runtime(
            DiagCode::InvalidRuleForm,
            "entry rule has no clauses",
        ));
    }

    // verify 100% static purity across transitive call graph
    let mut reachable_heads: Vec<SymId> = Vec::new();
    let mut seen: BTreeMap<SymId, u32> = BTreeMap::new();
    collect_reachable_pure_rules(arena, lexicon, entry_head, &mut reachable_heads, &mut seen)?;

    // function table layout:
    //   0..N       : internal compiled rules (each takes arity i64 params -> returns i64)
    //   N          : exported `run(p0..pK, fuel_limit: i64) -> i64`
    //   N + 1      : exported `get_status() -> i32`
    //   N + 2      : exported `get_fuel_rem() -> i64`
    let n_rules = reachable_heads.len() as u32;
    let entry_arity = entry_clauses[0].params.len() as u32;

    // 1. types section
    let mut type_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();

    for &h in &reachable_heads {
        let clauses = lexicon.rules_for(h).unwrap();
        let arity = clauses[0].params.len();
        let ty = (vec![VAL_I64; arity], vec![VAL_I64]);
        let tid = intern_type(&mut type_entries, ty);
        func_type_indices.push(tid);
    }
    // `run(args..., fuel_limit) -> i64`
    let run_tid = intern_type(
        &mut type_entries,
        (vec![VAL_I64; (entry_arity + 1) as usize], vec![VAL_I64]),
    );
    func_type_indices.push(run_tid);
    // `get_status() -> i32`
    let status_tid = intern_type(&mut type_entries, (vec![], vec![VAL_I32]));
    func_type_indices.push(status_tid);
    // `get_fuel_rem() -> i64`
    let fuel_tid = intern_type(&mut type_entries, (vec![], vec![VAL_I64]));
    func_type_indices.push(fuel_tid);

    // 2. compile every internal rule body
    let mut code_bodies: Vec<Vec<u8>> = Vec::with_capacity((n_rules + 3) as usize);
    for &h in &reachable_heads {
        let clauses = lexicon.rules_for(h).unwrap();
        let body = emit_rule_func(arena, clauses, &seen)?;
        code_bodies.push(body);
    }

    // 3. emit `run(p0..pK, fuel_limit)` wrapper
    {
        let mut b = Vec::new();
        // 0 local decl groups
        b.push(0);
        // global.set $fuel = local.get $entry_arity
        b.push(OP_LOCAL_GET);
        encode_u32(&mut b, entry_arity);
        b.push(OP_GLOBAL_SET);
        encode_u32(&mut b, GLOBAL_FUEL);
        // global.set $status = 0
        b.push(OP_I32_CONST);
        encode_i32(&mut b, WASM_STATUS_OK);
        b.push(OP_GLOBAL_SET);
        encode_u32(&mut b, GLOBAL_STATUS);
        // push args and call func 0 (entry)
        for i in 0..entry_arity {
            b.push(OP_LOCAL_GET);
            encode_u32(&mut b, i);
        }
        b.push(OP_CALL);
        encode_u32(&mut b, 0);
        b.push(OP_END);
        code_bodies.push(b);
    }

    // 4. emit `get_status() -> i32`
    {
        let mut b = vec![0, OP_GLOBAL_GET];
        encode_u32(&mut b, GLOBAL_STATUS);
        b.push(OP_END);
        code_bodies.push(b);
    }

    // 5. emit `get_fuel_rem() -> i64`
    {
        let mut b = vec![0, OP_GLOBAL_GET];
        encode_u32(&mut b, GLOBAL_FUEL);
        b.push(OP_END);
        code_bodies.push(b);
    }

    // 6. assemble binary wasm 1.0 module
    let mut wasm = Vec::new();
    wasm.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]); // \0asm v1

    // type section
    {
        let mut sec = Vec::new();
        encode_u32(&mut sec, type_entries.len() as u32);
        for (params, results) in &type_entries {
            sec.push(0x60);
            encode_u32(&mut sec, params.len() as u32);
            sec.extend_from_slice(params);
            encode_u32(&mut sec, results.len() as u32);
            sec.extend_from_slice(results);
        }
        emit_section(&mut wasm, SEC_TYPE, &sec);
    }

    // function section
    {
        let mut sec = Vec::new();
        encode_u32(&mut sec, func_type_indices.len() as u32);
        for &tid in &func_type_indices {
            encode_u32(&mut sec, tid);
        }
        emit_section(&mut wasm, SEC_FUNCTION, &sec);
    }

    // global section: ($fuel: mut i64 = 0, $status: mut i32 = 0)
    {
        let mut sec = Vec::new();
        encode_u32(&mut sec, 2);
        // global 0: mut i64 = 0
        sec.push(VAL_I64);
        sec.push(0x01); // mut
        sec.push(OP_I64_CONST);
        encode_i64(&mut sec, 0);
        sec.push(OP_END);
        // global 1: mut i32 = 0
        sec.push(VAL_I32);
        sec.push(0x01); // mut
        sec.push(OP_I32_CONST);
        encode_i32(&mut sec, 0);
        sec.push(OP_END);
        emit_section(&mut wasm, SEC_GLOBAL, &sec);
    }

    // export section
    {
        let mut sec = Vec::new();
        encode_u32(&mut sec, 3);
        emit_export(&mut sec, "run", 0x00, n_rules);
        emit_export(&mut sec, "get_status", 0x00, n_rules + 1);
        emit_export(&mut sec, "get_fuel_rem", 0x00, n_rules + 2);
        emit_section(&mut wasm, SEC_EXPORT, &sec);
    }

    // code section
    {
        let mut sec = Vec::new();
        encode_u32(&mut sec, code_bodies.len() as u32);
        for body in &code_bodies {
            encode_u32(&mut sec, body.len() as u32);
            sec.extend_from_slice(body);
        }
        emit_section(&mut wasm, SEC_CODE, &sec);
    }

    let wasm_hash = sha256(&wasm);
    Ok(WasmReflex {
        entry_name: String::from(arena.sym_name(entry_head)),
        arity: entry_arity,
        lexicon_hash: lexicon.hash(arena),
        rule_hash: entry_clauses[0].canonical_hash,
        wasm_bytes: wasm,
        wasm_hash,
    })
}

fn collect_reachable_pure_rules(
    arena: &Arena,
    lexicon: &Lexicon,
    head: SymId,
    order: &mut Vec<SymId>,
    index_map: &mut BTreeMap<SymId, u32>,
) -> Result<(), Diag> {
    if index_map.contains_key(&head) {
        return Ok(());
    }
    let clauses = lexicon.rules_for(head).ok_or_else(|| {
        Diag::runtime(
            DiagCode::InvalidRuleForm,
            format!("undefined callee '{}' in wasm reflex", arena.sym_name(head)),
        )
    })?;
    let expected_arity = clauses[0].params.len();
    for r in clauses {
        if !r.direct_caps.is_empty() {
            return Err(Diag::runtime(
                DiagCode::CapabilityEscalation,
                format!(
                    "cannot compile effectful rule '{}' to pure wasm reflex",
                    arena.sym_name(head)
                ),
            ));
        }
        if r.params.len() != expected_arity {
            return Err(Diag::runtime(
                DiagCode::ArityMismatch,
                "wasm reflex requires uniform arity across clauses",
            ));
        }
    }
    let idx = order.len() as u32;
    order.push(head);
    index_map.insert(head, idx);

    for r in clauses {
        for &callee in &r.direct_calls {
            collect_reachable_pure_rules(arena, lexicon, callee, order, index_map)?;
        }
    }
    Ok(())
}

fn emit_rule_func(
    arena: &Arena,
    clauses: &[Rule],
    fn_map: &BTreeMap<SymId, u32>,
) -> Result<Vec<u8>, Diag> {
    let arity = clauses[0].params.len() as u32;
    // 2 scratch i64 locals for div/mod zero checks: local `arity` and `arity + 1`
    let tmp_a = arity;
    let tmp_b = arity + 1;

    let mut b = Vec::new();
    // 1 local declaration group: 2 x i64
    encode_u32(&mut b, 1);
    encode_u32(&mut b, 2);
    b.push(VAL_I64);

    // fuel check at function entry:
    // if ($status != 0) return 0
    b.push(OP_GLOBAL_GET);
    encode_u32(&mut b, GLOBAL_STATUS);
    b.push(OP_I32_CONST);
    encode_i32(&mut b, 0);
    b.push(OP_I32_NE);
    b.push(OP_IF);
    b.push(0x40); // void block
    b.push(OP_I64_CONST);
    encode_i64(&mut b, 0);
    b.push(OP_RETURN);
    b.push(OP_END);

    // if ($fuel <= 0) { $status = 1; return 0; }
    b.push(OP_GLOBAL_GET);
    encode_u32(&mut b, GLOBAL_FUEL);
    b.push(OP_I64_CONST);
    encode_i64(&mut b, 0);
    b.push(OP_I64_LE_S);
    b.push(OP_IF);
    b.push(0x40);
    b.push(OP_I32_CONST);
    encode_i32(&mut b, WASM_STATUS_EXHAUSTED);
    b.push(OP_GLOBAL_SET);
    encode_u32(&mut b, GLOBAL_STATUS);
    b.push(OP_I64_CONST);
    encode_i64(&mut b, 0);
    b.push(OP_RETURN);
    b.push(OP_END);

    // $fuel = $fuel - 1
    b.push(OP_GLOBAL_GET);
    encode_u32(&mut b, GLOBAL_FUEL);
    b.push(OP_I64_CONST);
    encode_i64(&mut b, 1);
    b.push(OP_I64_SUB);
    b.push(OP_GLOBAL_SET);
    encode_u32(&mut b, GLOBAL_FUEL);

    // emit each clause in order
    for clause in clauses {
        let mut env: BTreeMap<SymId, u32> = BTreeMap::new();
        let mut guards: Vec<(u32, i64)> = Vec::new();
        for (i, pat) in clause.params.iter().enumerate() {
            match pat {
                Pattern::Wild => {}
                Pattern::Var(v) => {
                    env.insert(*v, i as u32);
                }
                Pattern::Int(lit) => {
                    guards.push((i as u32, *lit));
                }
                _ => {
                    return Err(Diag::runtime(
                        DiagCode::TypeMismatch,
                        "tier-2 wasm i64 reflex only supports int/var/wild parameter patterns",
                    ));
                }
            }
        }

        if guards.is_empty() {
            emit_i64_expr(arena, clause.body, &env, fn_map, tmp_a, tmp_b, &mut b)?;
            b.push(OP_RETURN);
        } else {
            // push conjunction of all int literal guards
            for (gi, &(param_idx, lit)) in guards.iter().enumerate() {
                b.push(OP_LOCAL_GET);
                encode_u32(&mut b, param_idx);
                b.push(OP_I64_CONST);
                encode_i64(&mut b, lit);
                b.push(OP_I64_EQ);
                if gi > 0 {
                    b.push(OP_I32_AND);
                }
            }
            b.push(OP_IF);
            b.push(0x40);
            emit_i64_expr(arena, clause.body, &env, fn_map, tmp_a, tmp_b, &mut b)?;
            b.push(OP_RETURN);
            b.push(OP_END);
        }
    }

    // fallback return 0 if no clause matched
    b.push(OP_I64_CONST);
    encode_i64(&mut b, 0);
    b.push(OP_END);
    Ok(b)
}

fn emit_i64_expr(
    arena: &Arena,
    term: TermId,
    env: &BTreeMap<SymId, u32>,
    fn_map: &BTreeMap<SymId, u32>,
    tmp_a: u32,
    tmp_b: u32,
    b: &mut Vec<u8>,
) -> Result<(), Diag> {
    match arena.node(term) {
        Node::Int(v) => {
            b.push(OP_I64_CONST);
            encode_i64(b, *v);
            Ok(())
        }
        Node::Var(v) => {
            let &slot = env.get(v).ok_or_else(|| {
                Diag::runtime(
                    DiagCode::UnboundVar,
                    format!("unbound var '?{}' in wasm compiler", arena.sym_name(*v)),
                )
            })?;
            b.push(OP_LOCAL_GET);
            encode_u32(b, slot);
            Ok(())
        }
        Node::App(head, args) => match *head {
            sym::ADD | sym::SUB | sym::MUL => {
                if args.len() != 2 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "binary op expects 2 args"));
                }
                emit_i64_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                emit_i64_expr(arena, args[1], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(match *head {
                    sym::ADD => OP_I64_ADD,
                    sym::SUB => OP_I64_SUB,
                    _ => OP_I64_MUL,
                });
                Ok(())
            }
            sym::DIV | sym::MOD => {
                if args.len() != 2 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "div/mod expects 2 args"));
                }
                emit_i64_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_LOCAL_SET);
                encode_u32(b, tmp_a);
                emit_i64_expr(arena, args[1], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_LOCAL_TEE);
                encode_u32(b, tmp_b);
                b.push(OP_I64_EQZ);
                b.push(OP_IF);
                b.push(VAL_I64);
                b.push(OP_I32_CONST);
                encode_i32(b, WASM_STATUS_DIV_ZERO);
                b.push(OP_GLOBAL_SET);
                encode_u32(b, GLOBAL_STATUS);
                b.push(OP_I64_CONST);
                encode_i64(b, 0);
                b.push(OP_ELSE);
                b.push(OP_LOCAL_GET);
                encode_u32(b, tmp_a);
                b.push(OP_LOCAL_GET);
                encode_u32(b, tmp_b);
                b.push(if *head == sym::DIV {
                    OP_I64_DIV_S
                } else {
                    OP_I64_REM_S
                });
                b.push(OP_END);
                Ok(())
            }
            sym::NEG => {
                if args.len() != 1 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "neg expects 1 arg"));
                }
                b.push(OP_I64_CONST);
                encode_i64(b, 0);
                emit_i64_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_I64_SUB);
                Ok(())
            }
            sym::IF => {
                if args.len() != 3 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "if expects 3 args"));
                }
                emit_bool_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_IF);
                b.push(VAL_I64);
                emit_i64_expr(arena, args[1], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_ELSE);
                emit_i64_expr(arena, args[2], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_END);
                Ok(())
            }
            callee => {
                let &fn_idx = fn_map.get(&callee).ok_or_else(|| {
                    Diag::runtime(
                        DiagCode::TypeMismatch,
                        format!(
                            "unsupported op '{}' in tier-2 wasm i64 reflex",
                            arena.sym_name(callee)
                        ),
                    )
                })?;
                for &a in args.iter() {
                    emit_i64_expr(arena, a, env, fn_map, tmp_a, tmp_b, b)?;
                }
                b.push(OP_CALL);
                encode_u32(b, fn_idx);
                Ok(())
            }
        },
        _ => Err(Diag::runtime(
            DiagCode::TypeMismatch,
            "expression is not a pure i64 term",
        )),
    }
}

fn emit_bool_expr(
    arena: &Arena,
    term: TermId,
    env: &BTreeMap<SymId, u32>,
    fn_map: &BTreeMap<SymId, u32>,
    tmp_a: u32,
    tmp_b: u32,
    b: &mut Vec<u8>,
) -> Result<(), Diag> {
    match arena.node(term) {
        Node::Sym(sym::TRUE) => {
            b.push(OP_I32_CONST);
            encode_i32(b, 1);
            Ok(())
        }
        Node::Sym(sym::FALSE) => {
            b.push(OP_I32_CONST);
            encode_i32(b, 0);
            Ok(())
        }
        Node::App(head, args) => match *head {
            sym::EQ | sym::LT | sym::LE | sym::GT | sym::GE => {
                if args.len() != 2 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "comparison expects 2 args"));
                }
                emit_i64_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                emit_i64_expr(arena, args[1], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(match *head {
                    sym::EQ => OP_I64_EQ,
                    sym::LT => OP_I64_LT_S,
                    sym::LE => OP_I64_LE_S,
                    sym::GT => OP_I64_GT_S,
                    _ => OP_I64_GE_S,
                });
                Ok(())
            }
            sym::NOT => {
                if args.len() != 1 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "not expects 1 arg"));
                }
                emit_bool_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(OP_I32_EQZ);
                Ok(())
            }
            sym::AND | sym::OR => {
                if args.len() != 2 {
                    return Err(Diag::runtime(DiagCode::ArityMismatch, "and/or expects 2 args"));
                }
                emit_bool_expr(arena, args[0], env, fn_map, tmp_a, tmp_b, b)?;
                emit_bool_expr(arena, args[1], env, fn_map, tmp_a, tmp_b, b)?;
                b.push(if *head == sym::AND {
                    OP_I32_AND
                } else {
                    OP_I32_OR
                });
                Ok(())
            }
            _ => Err(Diag::runtime(
                DiagCode::TypeMismatch,
                "expected boolean expression in if condition",
            )),
        },
        _ => Err(Diag::runtime(
            DiagCode::TypeMismatch,
            "expected boolean expression in if condition",
        )),
    }
}

fn intern_type(table: &mut Vec<(Vec<u8>, Vec<u8>)>, ty: (Vec<u8>, Vec<u8>)) -> u32 {
    if let Some(pos) = table.iter().position(|t| *t == ty) {
        return pos as u32;
    }
    let id = table.len() as u32;
    table.push(ty);
    id
}

fn emit_section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id);
    encode_u32(out, payload.len() as u32);
    out.extend_from_slice(payload);
}

fn emit_export(out: &mut Vec<u8>, name: &str, kind: u8, idx: u32) {
    encode_u32(out, name.len() as u32);
    out.extend_from_slice(name.as_bytes());
    out.push(kind);
    encode_u32(out, idx);
}

fn encode_u32(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn encode_i32(out: &mut Vec<u8>, mut v: i32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn encode_i64(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// built-in pure-rust mvp wasm decoder & differential-oracle executor
// proves bit-for-bit parity between emitted `.wasm` bytes and symbolic `eval`
// without any external wasm runtime dependency!
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum WVal {
    I32(i32),
    I64(i64),
}

impl WVal {
    fn as_i32(self) -> Result<i32, Diag> {
        match self {
            WVal::I32(v) => Ok(v),
            _ => Err(Diag::runtime(DiagCode::TypeMismatch, "wasm expected i32")),
        }
    }
    fn as_i64(self) -> Result<i64, Diag> {
        match self {
            WVal::I64(v) => Ok(v),
            _ => Err(Diag::runtime(DiagCode::TypeMismatch, "wasm expected i64")),
        }
    }
}

struct DecodedFunc {
    param_count: usize,
    extra_locals: usize,
    code: Vec<u8>,
}

struct DecodedModule {
    funcs: Vec<DecodedFunc>,
    exports: BTreeMap<String, u32>,
}

/// decode and execute a compiled `WasmReflex` binary using the built-in deterministic
/// mvp wasm differential-oracle interpreter.
pub fn exec_wasm_reflex(
    wasm_bytes: &[u8],
    args: &[i64],
    fuel_limit: u64,
) -> Result<WasmExecResult, Diag> {
    let module = decode_wasm(wasm_bytes)?;
    let &run_idx = module
        .exports
        .get("run")
        .ok_or_else(|| Diag::runtime(DiagCode::InvalidRuleForm, "wasm missing 'run' export"))?;
    let mut call_args: Vec<WVal> = args.iter().map(|&v| WVal::I64(v)).collect();
    call_args.push(WVal::I64(fuel_limit as i64));

    let mut globals = [WVal::I64(0), WVal::I32(0)];
    let ret = exec_func(&module, run_idx as usize, &call_args, &mut globals, 0)?;
    let value = ret.map(|v| v.as_i64()).transpose()?.unwrap_or(0);
    let fuel_rem = globals[GLOBAL_FUEL as usize].as_i64()?.max(0) as u64;
    let status = globals[GLOBAL_STATUS as usize].as_i32()?;

    Ok(WasmExecResult {
        status,
        value,
        fuel_used: fuel_limit.saturating_sub(fuel_rem),
    })
}

fn decode_wasm(bytes: &[u8]) -> Result<DecodedModule, Diag> {
    if bytes.len() < 8 || &bytes[0..8] != b"\x00asm\x01\x00\x00\x00" {
        return Err(Diag::runtime(DiagCode::InvalidRuleForm, "invalid wasm header"));
    }
    let mut pos = 8usize;
    let mut types: Vec<usize> = Vec::new();
    let mut func_types: Vec<u32> = Vec::new();
    let mut exports: BTreeMap<String, u32> = BTreeMap::new();
    let mut funcs: Vec<DecodedFunc> = Vec::new();

    while pos < bytes.len() {
        let sec_id = bytes[pos];
        pos += 1;
        let sec_len = decode_u32(bytes, &mut pos)? as usize;
        let sec_end = pos + sec_len;
        if sec_end > bytes.len() {
            return Err(Diag::runtime(DiagCode::InvalidRuleForm, "truncated wasm section"));
        }
        match sec_id {
            SEC_TYPE => {
                let count = decode_u32(bytes, &mut pos)?;
                for _ in 0..count {
                    if bytes[pos] != 0x60 {
                        return Err(Diag::runtime(DiagCode::InvalidRuleForm, "bad functype tag"));
                    }
                    pos += 1;
                    let p_len = decode_u32(bytes, &mut pos)? as usize;
                    pos += p_len;
                    let r_len = decode_u32(bytes, &mut pos)? as usize;
                    pos += r_len;
                    types.push(p_len);
                }
            }
            SEC_FUNCTION => {
                let count = decode_u32(bytes, &mut pos)?;
                for _ in 0..count {
                    func_types.push(decode_u32(bytes, &mut pos)?);
                }
            }
            SEC_EXPORT => {
                let count = decode_u32(bytes, &mut pos)?;
                for _ in 0..count {
                    let nlen = decode_u32(bytes, &mut pos)? as usize;
                    let name = core::str::from_utf8(&bytes[pos..pos + nlen])
                        .map_err(|_| Diag::runtime(DiagCode::InvalidRuleForm, "bad export utf8"))?;
                    pos += nlen;
                    let kind = bytes[pos];
                    pos += 1;
                    let idx = decode_u32(bytes, &mut pos)?;
                    if kind == 0x00 {
                        exports.insert(String::from(name), idx);
                    }
                }
            }
            SEC_CODE => {
                let count = decode_u32(bytes, &mut pos)?;
                for fi in 0..count as usize {
                    let body_len = decode_u32(bytes, &mut pos)? as usize;
                    let body_end = pos + body_len;
                    let groups = decode_u32(bytes, &mut pos)?;
                    let mut extra = 0usize;
                    for _ in 0..groups {
                        let c = decode_u32(bytes, &mut pos)? as usize;
                        pos += 1; // valtype
                        extra += c;
                    }
                    let code = bytes[pos..body_end].to_vec();
                    pos = body_end;
                    let param_count = types[func_types[fi] as usize];
                    funcs.push(DecodedFunc {
                        param_count,
                        extra_locals: extra,
                        code,
                    });
                }
            }
            _ => {}
        }
        pos = sec_end;
    }

    Ok(DecodedModule { funcs, exports })
}

fn exec_func(
    module: &DecodedModule,
    fn_idx: usize,
    args: &[WVal],
    globals: &mut [WVal; 2],
    depth: usize,
) -> Result<Option<WVal>, Diag> {
    if depth > 512 {
        globals[GLOBAL_STATUS as usize] = WVal::I32(WASM_STATUS_EXHAUSTED);
        return Ok(Some(WVal::I64(0)));
    }
    let f = &module.funcs[fn_idx];
    let mut locals = Vec::with_capacity(f.param_count + f.extra_locals);
    locals.extend_from_slice(args);
    for _ in 0..f.extra_locals {
        locals.push(WVal::I64(0));
    }

    let code = &f.code;
    let mut pc = 0usize;
    let mut stack: Vec<WVal> = Vec::with_capacity(16);

    while pc < code.len() {
        let op = code[pc];
        pc += 1;
        match op {
            OP_END => {
                if pc >= code.len() {
                    return Ok(stack.pop());
                }
            }
            OP_RETURN => {
                return Ok(stack.pop());
            }
            OP_BLOCK => {
                pc += 1; // blocktype
            }
            OP_IF => {
                let _bt = code[pc];
                pc += 1;
                let cond = stack
                    .pop()
                    .ok_or_else(|| Diag::runtime(DiagCode::TypeMismatch, "wasm stack underflow"))?
                    .as_i32()?;
                if cond == 0 {
                    // skip to matching ELSE or END
                    let (found_else, next_pc) = skip_structured(code, pc, true)?;
                    pc = next_pc;
                    let _ = found_else;
                }
            }
            OP_ELSE => {
                // we executed the true branch; skip the else branch to matching END
                let (_, next_pc) = skip_structured(code, pc, false)?;
                pc = next_pc;
            }
            OP_BR | OP_BR_IF => {
                let _depth = decode_u32(code, &mut pc)?;
            }
            OP_DROP => {
                stack.pop();
            }
            OP_CALL => {
                let callee = decode_u32(code, &mut pc)? as usize;
                let n = module.funcs[callee].param_count;
                let start = stack.len().saturating_sub(n);
                let sub_args: Vec<WVal> = stack.drain(start..).collect();
                if let Some(res) = exec_func(module, callee, &sub_args, globals, depth + 1)? {
                    stack.push(res);
                }
            }
            OP_LOCAL_GET => {
                let idx = decode_u32(code, &mut pc)? as usize;
                stack.push(locals[idx]);
            }
            OP_LOCAL_SET => {
                let idx = decode_u32(code, &mut pc)? as usize;
                locals[idx] = stack.pop().unwrap();
            }
            OP_LOCAL_TEE => {
                let idx = decode_u32(code, &mut pc)? as usize;
                locals[idx] = *stack.last().unwrap();
            }
            OP_GLOBAL_GET => {
                let idx = decode_u32(code, &mut pc)? as usize;
                stack.push(globals[idx]);
            }
            OP_GLOBAL_SET => {
                let idx = decode_u32(code, &mut pc)? as usize;
                globals[idx] = stack.pop().unwrap();
            }
            OP_I32_CONST => {
                let v = decode_i32(code, &mut pc)?;
                stack.push(WVal::I32(v));
            }
            OP_I64_CONST => {
                let v = decode_i64(code, &mut pc)?;
                stack.push(WVal::I64(v));
            }
            OP_I32_EQZ => {
                let a = stack.pop().unwrap().as_i32()?;
                stack.push(WVal::I32(if a == 0 { 1 } else { 0 }));
            }
            OP_I32_NE => {
                let b = stack.pop().unwrap().as_i32()?;
                let a = stack.pop().unwrap().as_i32()?;
                stack.push(WVal::I32(if a != b { 1 } else { 0 }));
            }
            OP_I32_AND => {
                let b = stack.pop().unwrap().as_i32()?;
                let a = stack.pop().unwrap().as_i32()?;
                stack.push(WVal::I32(a & b));
            }
            OP_I32_OR => {
                let b = stack.pop().unwrap().as_i32()?;
                let a = stack.pop().unwrap().as_i32()?;
                stack.push(WVal::I32(a | b));
            }
            OP_I64_EQZ => {
                let a = stack.pop().unwrap().as_i64()?;
                stack.push(WVal::I32(if a == 0 { 1 } else { 0 }));
            }
            OP_I64_EQ | OP_I64_LT_S | OP_I64_GT_S | OP_I64_LE_S | OP_I64_GE_S => {
                let b = stack.pop().unwrap().as_i64()?;
                let a = stack.pop().unwrap().as_i64()?;
                let res = match op {
                    OP_I64_EQ => a == b,
                    OP_I64_LT_S => a < b,
                    OP_I64_GT_S => a > b,
                    OP_I64_LE_S => a <= b,
                    _ => a >= b,
                };
                stack.push(WVal::I32(if res { 1 } else { 0 }));
            }
            OP_I64_ADD | OP_I64_SUB | OP_I64_MUL | OP_I64_DIV_S | OP_I64_REM_S => {
                let b = stack.pop().unwrap().as_i64()?;
                let a = stack.pop().unwrap().as_i64()?;
                let res = match op {
                    OP_I64_ADD => a.wrapping_add(b),
                    OP_I64_SUB => a.wrapping_sub(b),
                    OP_I64_MUL => a.wrapping_mul(b),
                    OP_I64_DIV_S => a.wrapping_div(b),
                    _ => a.wrapping_rem(b),
                };
                stack.push(WVal::I64(res));
            }
            other => {
                return Err(Diag::runtime(
                    DiagCode::InvalidRuleForm,
                    format!("unsupported wasm opcode 0x{:02x}", other),
                ));
            }
        }
    }
    Ok(stack.pop())
}

fn skip_structured(code: &[u8], mut pc: usize, stop_at_else: bool) -> Result<(bool, usize), Diag> {
    let mut nesting = 0usize;
    while pc < code.len() {
        let op = code[pc];
        pc += 1;
        match op {
            OP_BLOCK | OP_IF => {
                pc += 1; // blocktype
                nesting += 1;
            }
            OP_ELSE => {
                if nesting == 0 && stop_at_else {
                    return Ok((true, pc));
                }
            }
            OP_END => {
                if nesting == 0 {
                    return Ok((false, pc));
                }
                nesting -= 1;
            }
            OP_BR | OP_BR_IF | OP_CALL | OP_LOCAL_GET | OP_LOCAL_SET | OP_LOCAL_TEE
            | OP_GLOBAL_GET | OP_GLOBAL_SET => {
                let _ = decode_u32(code, &mut pc)?;
            }
            OP_I32_CONST => {
                let _ = decode_i32(code, &mut pc)?;
            }
            OP_I64_CONST => {
                let _ = decode_i64(code, &mut pc)?;
            }
            _ => {}
        }
    }
    Err(Diag::runtime(DiagCode::InvalidRuleForm, "unterminated wasm block"))
}

fn decode_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, Diag> {
    let mut res = 0u32;
    let mut shift = 0u32;
    loop {
        let b = *bytes
            .get(*pos)
            .ok_or_else(|| Diag::runtime(DiagCode::InvalidRuleForm, "truncated leb128 u32"))?;
        *pos += 1;
        res |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok(res);
        }
        shift += 7;
    }
}

fn decode_i32(bytes: &[u8], pos: &mut usize) -> Result<i32, Diag> {
    let mut res = 0i32;
    let mut shift = 0u32;
    let mut byte;
    loop {
        byte = *bytes
            .get(*pos)
            .ok_or_else(|| Diag::runtime(DiagCode::InvalidRuleForm, "truncated leb128 i32"))?;
        *pos += 1;
        res |= ((byte & 0x7f) as i32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    if shift < 32 && (byte & 0x40) != 0 {
        res |= !0i32 << shift;
    }
    Ok(res)
}

fn decode_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, Diag> {
    let mut res = 0i64;
    let mut shift = 0u32;
    let mut byte;
    loop {
        byte = *bytes
            .get(*pos)
            .ok_or_else(|| Diag::runtime(DiagCode::InvalidRuleForm, "truncated leb128 i64"))?;
        *pos += 1;
        res |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        res |= !0i64 << shift;
    }
    Ok(res)
}
