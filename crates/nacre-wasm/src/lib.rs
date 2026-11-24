//! zero-dep wasm32-unknown-unknown export surface for nacre-core.
//!
//! exposes deterministic evaluation, static capability analysis, autonomous reflex
//! crystallization (pure & hybrid guarded), `.ncrystal` bundle verification, and
//! tier-2 pure wasm reflex emission over a linear-memory byte buffer abi.

#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;

pub mod studio_ui;

use nacre_core::arena::Arena;
use nacre_core::bundle::CrystalBundle;
use nacre_core::eval::{eval, Outcome};
use nacre_core::fuel::Fuel;
use nacre_core::journal::run_and_record;
use nacre_core::lexicon::Lexicon;
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize_with_mode, SynthMode};
use nacre_core::wasm_emit::compile_pure_i64_reflex;

#[cfg(target_arch = "wasm32")]
const BUF_CAP: usize = 131_072;

#[cfg(target_arch = "wasm32")]
struct WasmBuffers {
    in_buf: [u8; BUF_CAP],
    out_buf: [u8; BUF_CAP],
    out_len: usize,
}

#[cfg(target_arch = "wasm32")]
struct SyncCell(RefCell<WasmBuffers>);

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
unsafe impl Sync for SyncCell {}

#[cfg(target_arch = "wasm32")]
static BUFFERS: SyncCell = SyncCell(RefCell::new(WasmBuffers {
    in_buf: [0u8; BUF_CAP],
    out_buf: [0u8; BUF_CAP],
    out_len: 0,
}));

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_in_ptr() -> *mut u8 {
    BUFFERS.0.borrow_mut().in_buf.as_mut_ptr()
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_in_cap() -> u32 {
    BUF_CAP as u32
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_out_ptr() -> *const u8 {
    BUFFERS.0.borrow().out_buf.as_ptr()
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_out_len() -> u32 {
    BUFFERS.0.borrow().out_len as u32
}

#[cfg(target_arch = "wasm32")]
fn read_in(len: u32) -> String {
    let b = BUFFERS.0.borrow();
    let n = (len as usize).min(BUF_CAP);
    String::from(core::str::from_utf8(&b.in_buf[..n]).unwrap_or(""))
}

#[cfg(target_arch = "wasm32")]
fn write_out_bytes(bytes: &[u8]) {
    let mut b = BUFFERS.0.borrow_mut();
    let n = bytes.len().min(BUF_CAP);
    b.out_buf[..n].copy_from_slice(&bytes[..n]);
    b.out_len = n;
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_eval(len: u32, fuel_limit: u64) -> u32 {
    let input = read_in(len);
    let (status, text) = eval_bundle(&input, fuel_limit);
    write_out_bytes(text.as_bytes());
    status
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_caps(len: u32) -> u32 {
    let input = read_in(len);
    let (status, text) = caps_bundle(&input);
    write_out_bytes(text.as_bytes());
    status
}

/// mode_flag: 0 = pure offline, >=1 = hybrid guarded with `min_support = mode_flag`.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_auto_crystallize(len: u32, mode_flag: u64) -> u32 {
    let input = read_in(len);
    let mode = if mode_flag == 0 {
        SynthMode::PureOffline
    } else {
        SynthMode::HybridGuarded {
            min_support: mode_flag as usize,
        }
    };
    let (status, text) = auto_crystallize_bundle(&input, mode);
    write_out_bytes(text.as_bytes());
    status
}

/// cryptographically verify a `.ncrystal` bundle offline. returns 0=verified, 3=invalid/tampered.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_verify_bundle(len: u32) -> u32 {
    let input = read_in(len);
    let (status, text) = verify_crystal_bundle(&input);
    write_out_bytes(text.as_bytes());
    status
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_compile_wasm_reflex(len: u32) -> u32 {
    let input = read_in(len);
    match compile_wasm_bundle(&input) {
        Ok(bytes) => {
            write_out_bytes(&bytes);
            0
        }
        Err(msg) => {
            write_out_bytes(msg.to_ascii_lowercase().as_bytes());
            3
        }
    }
}

/// pure-rust ui event dispatcher: reads `action\npayload` from `in_buf`, writes complete
/// strictly-lowercase html snapshot to `out_buf`. keeps js in template.html under ~40 lines!
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn nacre_ui_dispatch(len: u32) -> u32 {
    let input = read_in(len);
    let html = studio_ui::dispatch_ui_event(&input);
    write_out_bytes(html.as_bytes());
    0
}

pub fn eval_bundle(bundle: &str, fuel_limit: u64) -> (u32, String) {
    let (lex_src, expr_src) = match bundle.split_once("\n---\n") {
        Some((l, e)) => (l, e),
        None => ("", bundle),
    };

    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    if !lex_src.trim().is_empty() {
        if let Err(d) = lex.load_source(&mut arena, lex_src) {
            return (3, d.render_with_source(lex_src).to_ascii_lowercase());
        }
    }
    let expr = match parse_term(&mut arena, expr_src) {
        Ok(t) => t,
        Err(d) => return (3, d.render_with_source(expr_src).to_ascii_lowercase()),
    };
    let mut fuel = Fuel::new(fuel_limit);
    match eval(&mut arena, &lex, expr, &mut fuel) {
        Outcome::Done(v) => (
            0,
            format!(
                "status: done\nvalue:  {}\nhash:   {}\nfuel:   {}/{}\nnodes:  {}",
                print_term(&arena, v).to_ascii_lowercase(),
                arena.hash(v).short_hex(),
                fuel.used(),
                fuel.limit(),
                arena.live_node_count(v)
            ),
        ),
        Outcome::Yield { effect, resume } => (
            1,
            format!(
                "status:   yield\neffect:   {}\neff_hash: {}\nresidual: {}\nres_hash: {}\nfuel:     {}/{}",
                print_term(&arena, effect).to_ascii_lowercase(),
                arena.hash(effect).short_hex(),
                print_term(&arena, resume).to_ascii_lowercase(),
                arena.hash(resume).short_hex(),
                fuel.used(),
                fuel.limit()
            ),
        ),
        Outcome::Exhausted { resume } => (
            2,
            format!(
                "status:   exhausted\nresidual: {}\nres_hash: {}\nfuel:     {}/{}",
                print_term(&arena, resume).to_ascii_lowercase(),
                arena.hash(resume).short_hex(),
                fuel.used(),
                fuel.limit()
            ),
        ),
        Outcome::Fault(d) => (3, format!("{}", d).to_ascii_lowercase()),
    }
}

pub fn caps_bundle(bundle: &str) -> (u32, String) {
    let (lex_src, expr_src) = match bundle.split_once("\n---\n") {
        Some((l, e)) => (l, e),
        None => ("", bundle),
    };
    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    if !lex_src.trim().is_empty() {
        if let Err(d) = lex.load_source(&mut arena, lex_src) {
            return (3, d.render_with_source(lex_src).to_ascii_lowercase());
        }
    }
    let expr = match parse_term(&mut arena, expr_src) {
        Ok(t) => t,
        Err(d) => return (3, d.render_with_source(expr_src).to_ascii_lowercase()),
    };
    let caps = lex.static_cap_names(&arena, expr);
    let label = if caps.is_empty() {
        String::from("pure offline (0 caps)")
    } else {
        format!("[{}]", caps.join(", ").to_ascii_lowercase())
    };
    (0, format!("lexicon: {} | caps: {}", lex.hash(&arena).short_hex(), label))
}

pub fn auto_crystallize_bundle(bundle: &str, mode: SynthMode) -> (u32, String) {
    let (lex_src, samples_src) = match bundle.split_once("\n---\n") {
        Some((l, s)) => (l, s),
        None => {
            return (
                3,
                String::from("expected <lexicon>\\n---\\n<entry => reply lines>"),
            );
        }
    };

    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    if let Err(d) = lex.load_source(&mut arena, lex_src) {
        return (3, d.render_with_source(lex_src).to_ascii_lowercase());
    }

    let mut traces = Vec::new();
    for line in samples_src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let Some((entry_s, reply_s)) = trimmed.split_once("=>") else {
            return (
                3,
                format!("invalid trace sample line (expected `expr => reply`): {}", trimmed)
                    .to_ascii_lowercase(),
            );
        };
        let entry = match parse_term(&mut arena, entry_s.trim()) {
            Ok(t) => t,
            Err(d) => return (3, format!("{}", d).to_ascii_lowercase()),
        };
        let reply_owned = String::from(reply_s.trim());
        let tr = match run_and_record(&mut arena, &lex, entry, 5000, |a, _eff| {
            parse_term(a, &reply_owned)
        }) {
            Ok(t) => t,
            Err(d) => return (3, format!("{}", d).to_ascii_lowercase()),
        };
        traces.push(tr);
    }

    match auto_crystallize_with_mode(&mut arena, &lex, &traces, mode) {
        Ok(ac) => {
            let full_lex_src = ac.lexicon.to_source(&arena);
            let crystal_bundle =
                CrystalBundle::new(&ac.target_head, &full_lex_src, ac.cert.clone(), None);
            let bundle_wire = crystal_bundle.encode_text();
            let mode_str = match ac.mode {
                SynthMode::PureOffline => String::from("pure offline"),
                SynthMode::HybridGuarded { min_support } => {
                    format!("hybrid guarded (min_support={})", min_support)
                }
            };
            let summary = format!(
                "mode:        {}\ncert_hash:   {}\nbundle_hash: {}\nbase_lex:    {}\nnew_lex:     {}\ntraces:      {} (merkle {})\neffects:     {} -> {} (eliminated {})\ncaps:        [{}] -> [{}]\npure:        {}\n===synthesized===\n{}\n===promoted_lexicon===\n{}\n===ncrystal===\n{}",
                mode_str,
                ac.cert.cert_hash.short_hex(),
                crystal_bundle.bundle_hash.short_hex(),
                ac.cert.base_lexicon_hash.short_hex(),
                ac.cert.new_lexicon_hash.short_hex(),
                ac.cert.trace_count,
                ac.cert.traces_merkle_root.short_hex(),
                ac.cert.base_effects,
                ac.cert.new_effects,
                ac.cert.effects_eliminated(),
                ac.cert.caps_before.join(", "),
                ac.cert.caps_after.join(", "),
                ac.cert.is_now_pure(),
                ac.synthesized_src,
                full_lex_src,
                bundle_wire
            );
            (0, summary.to_ascii_lowercase())
        }
        Err(d) => (3, format!("{}", d).to_ascii_lowercase()),
    }
}

pub fn verify_crystal_bundle(wire: &str) -> (u32, String) {
    match CrystalBundle::decode_text(wire) {
        Ok(b) => match b.verify() {
            Ok(info) => (
                0,
                format!(
                    "verified:    true (cryptographic seal + static cap audit passed)\nname:        {}\nbundle_hash: {}\nlexicon:     {} ({} rules)\nstatic_caps: [{}]\noffline:     {}\neliminated:  {} external effects\n===lexicon===\n{}",
                    info.name,
                    info.bundle_hash.short_hex(),
                    info.lexicon_hash.short_hex(),
                    info.rule_count,
                    info.static_caps.join(", "),
                    info.is_pure,
                    info.effects_eliminated,
                    b.lexicon_src
                )
                .to_ascii_lowercase(),
            ),
            Err(d) => (3, format!("rejected: {}", d).to_ascii_lowercase()),
        },
        Err(d) => (3, format!("rejected: {}", d).to_ascii_lowercase()),
    }
}

pub fn compile_wasm_bundle(bundle: &str) -> Result<Vec<u8>, String> {
    let (lex_src, head_src) = bundle
        .split_once("\n---\n")
        .ok_or_else(|| String::from("expected <lexicon>\\n---\\n<rule_name>"))?;
    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, lex_src)
        .map_err(|d| d.render_with_source(lex_src))?;
    let head_name = head_src.trim();
    let head_sym = arena
        .lookup_sym(head_name)
        .ok_or_else(|| format!("unknown rule '{}'", head_name))?;
    let reflex = compile_pure_i64_reflex(&arena, &lex, head_sym).map_err(|d| format!("{}", d))?;
    Ok(reflex.wasm_bytes)
}
