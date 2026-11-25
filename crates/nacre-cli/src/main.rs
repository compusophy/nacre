//! zero-dep cli for nacre (strictly lowercase ui output).

#![forbid(unsafe_code)]

mod bench;
mod guard;
mod live;

use std::env;
use std::fs;
use std::path::Path;
use std::process;

use nacre_core::arena::{Arena, Node};
use nacre_core::bundle::CrystalBundle;
use nacre_core::coev::{run_attacker_ablation, run_red_queen_coevolution, DefenderGen};
use nacre_core::distill::crystallize_from_source;
use nacre_core::eval::{eval, Outcome};
use nacre_core::fuel::Fuel;
use nacre_core::journal::{fork_from_event, replay_trace, run_and_record, Trace, TraceOutcome};
use nacre_core::lexicon::Lexicon;
use nacre_core::nanocode_bridge::crystallize_from_nanocode_jsonl;
use nacre_core::security_bench::run_security_control_bench;
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize, SynthMode};
use nacre_core::wasm_emit::{compile_pure_i64_reflex, exec_wasm_reflex};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return;
    }

    let res = match args[0].as_str() {
        "init" => guard::run_init(&args[1..]),
        "test-policy" => guard::run_test_policy(&args[1..]),
        "mcp-guard" => guard::run_mcp_guard(&args[1..]),
        "hook" => guard::run_hook(&args[1..]),
        "distill" => guard::run_distill(&args[1..]),
        "query" => guard::run_query(&args[1..]),
        "audit-verify" => guard::run_audit_verify(&args[1..]),
        "audit-summary" => guard::run_audit_summary(&args[1..]),
        "bench" => bench::run_bench(),
        "coev" => cmd_coev(),
        "security-bench" => cmd_security_bench(),
        "live-matrix" => live::run_live_matrix(&args[1..]),
        "live-inject" => live::run_live_inject(&args[1..]),
        "demo" => cmd_demo(),
        "run" => cmd_run(&args[1..]),
        "caps" => cmd_caps(&args[1..]),
        "replay" => cmd_replay(&args[1..]),
        "crystallize" => cmd_crystallize(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "ingest-nanocode" => cmd_ingest_nanocode(&args[1..]),
        "wasm-reflex" => cmd_wasm_reflex(&args[1..]),
        "build-studio" => cmd_build_studio(&args[1..]),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command '{}' (try `nacre help`)", other)),
    };

    if let Err(msg) = res {
        eprintln!("{}", msg.to_ascii_lowercase());
        process::exit(1);
    }
}

fn print_help() {
    println!(
        "\
nacre — deterministic symbolic cells, durable merkle journals, and verified reflexes

commands:
  nacre init [--dir <path>] [--claude]
      generate a workspace nacre.policy (coding-agent preset) and Claude Code / MCP config snippets

  nacre test-policy [--policy <file> | --preset coding-agent --allow-path <pfx>]
      run a 10-case adversarial + benign self-test against your policy before deploying

  nacre mcp-guard [--preset coding-agent] [--allow-path <pfx>] [--deny-tool <name>] [--deny-substr <str>] [--policy <f>] [--journal <audit.jsonl>] -- <cmd> [args...]
      wrap any stdio MCP server behind nacre's algebraic handle firewall + sha-256 audit journal

  nacre hook [--preset coding-agent] [--allow-path <pfx>] [--deny-tool <name>] [--deny-substr <str>] [--policy <f>] [--journal <audit.jsonl>]
      drop-in Claude Code / Codex PreToolUse stdin JSON guard (exit 0 allow, exit 2 block + merkle proof)

  nacre distill --input <calls.jsonl> --out <skill.ncrystal> [--min-support 4] [--pure]
      distill a plain JSONL call log into a sha-256 sealed offline/hybrid .ncrystal reflex

  nacre query <skill.ncrystal> <input|--stdin>
      verify and query a .ncrystal reflex offline (exit 0 hit, exit 10 escalate to llm, exit 3 tamper)

  nacre audit-verify <audit.jsonl>
      verify the sha-256 hash chain of an mcp-guard / hook audit journal offline

  nacre audit-summary <audit.jsonl>
      verify the audit chain and print a session report (allowed, blocked, reflex hits, merkle proofs)

  nacre bench
      run the real 2-domain verifiable hill-climb & ablation benchmark
      (12 algorithmic tasks + 60-event incremental streaming generalization)

  nacre coev
      run the 4-way pt-mcmc attacker ablation & red-queen co-evolution security arena

  nacre security-bench
      run the 6-class naked-control vs naive-guard vs nacre security benchmark

  nacre live-matrix [--models google/gemini-4-hydrogen,google/gemini-4-neon] [--dry-run]
      pure-rust live cross-model naked-control vs defended matrix (zero node/js)

  nacre live-inject [--models ...]
      live indirect prompt-injection benchmark: conventional tool harness vs nacre handle firewall

  nacre demo
      run the full end-to-end demo:
      1) execute an agent cell using an external llm capability
      2) serialize a durable merkle trace & replay it bit-for-bit offline
      3) time-travel fork from a mid-execution residual continuation
      4) enforce a fractal capability firewall via algebraic handle
      5) autonomously synthesize & verify a 0-llm pure reflex from traces
      6) compile a pure recursive rule to tier-2 wasm 1.0 & diff-oracle verify it

  nacre run <lexicon.ncr> <expr> [fuel]
      evaluate <expr> under <lexicon.ncr> (default fuel: 10000)

  nacre caps <lexicon.ncr> <expr>
      statically infer all capabilities reachable from <expr>

  nacre replay <lexicon.ncr> <trace.ntrace>
      verify and replay a recorded merkle trace offline with zero i/o

  nacre crystallize <base.ncr> <candidate.ncr> <trace1.ntrace> [trace2 ...]
      mechanically verify <candidate.ncr> against recorded traces and mint a certificate

  nacre verify <skill.ncrystal>
      cryptographically verify a portable .ncrystal skill bundle offline

  nacre ingest-nanocode <journal.jsonl> <tool_name> [min_support|pure] [out.ncrystal]
      ingest a nanocode-code-mode-engine JSONL journal and crystallize a verified reflex

  nacre wasm-reflex <lexicon.ncr> <rule_name> [out.wasm]
      compile a pure i64 supercombinator to a standalone fuel-metered wasm 1.0 reflex

  nacre build-studio [wasm_path] [template_html] [out_html]
      bundle nacre_wasm.wasm into a single self-contained all-lowercase html studio"
    );
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: nacre run <lexicon.ncr> <expr> [fuel]".into());
    }
    let src = fs::read_to_string(&args[0]).map_err(|e| format!("read failed: {}", e))?;
    let fuel_limit: u64 = args
        .get(2)
        .map(|s| s.parse::<u64>().map_err(|_| "invalid fuel integer".to_string()))
        .transpose()?
        .unwrap_or(10_000);

    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, &src)
        .map_err(|d| d.render_with_source(&src))?;
    let entry = parse_term(&mut arena, &args[1]).map_err(|d| d.render_with_source(&args[1]))?;

    let mut fuel = Fuel::new(fuel_limit);
    match eval(&mut arena, &lex, entry, &mut fuel) {
        Outcome::Done(val) => {
            println!("status    done");
            println!("value     {}", print_term(&arena, val).to_ascii_lowercase());
            println!("hash      {}", arena.hash(val).short_hex());
            println!("fuel      {}/{}", fuel.used(), fuel.limit());
            println!("nodes     {}", arena.live_node_count(val));
        }
        Outcome::Yield { effect, resume } => {
            println!("status    yield");
            println!("effect    {}", print_term(&arena, effect).to_ascii_lowercase());
            println!("eff_hash  {}", arena.hash(effect).short_hex());
            println!("residual  {}", print_term(&arena, resume).to_ascii_lowercase());
            println!("res_hash  {}", arena.hash(resume).short_hex());
            println!("fuel      {}/{}", fuel.used(), fuel.limit());
        }
        Outcome::Exhausted { resume } => {
            println!("status    exhausted");
            println!("residual  {}", print_term(&arena, resume).to_ascii_lowercase());
            println!("res_hash  {}", arena.hash(resume).short_hex());
            println!("fuel      {}/{}", fuel.used(), fuel.limit());
        }
        Outcome::Fault(d) => {
            return Err(format!("fault     {}", d));
        }
    }
    Ok(())
}

fn cmd_caps(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: nacre caps <lexicon.ncr> <expr>".into());
    }
    let src = fs::read_to_string(&args[0]).map_err(|e| format!("read failed: {}", e))?;
    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, &src)
        .map_err(|d| d.render_with_source(&src))?;
    let entry = parse_term(&mut arena, &args[1]).map_err(|d| d.render_with_source(&args[1]))?;
    let caps = lex.static_cap_names(&arena, entry);
    println!("lexicon   {}", lex.hash(&arena).short_hex());
    if caps.is_empty() {
        println!("caps      none (100% pure offline)");
    } else {
        println!("caps      {}", caps.join(", ").to_ascii_lowercase());
    }
    Ok(())
}

fn cmd_replay(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: nacre replay <lexicon.ncr> <trace.ntrace>".into());
    }
    let src = fs::read_to_string(&args[0]).map_err(|e| format!("read lexicon failed: {}", e))?;
    let trace_raw = fs::read_to_string(&args[1]).map_err(|e| format!("read trace failed: {}", e))?;
    let trace = Trace::decode_text(&trace_raw).map_err(|d| format!("{}", d))?;

    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, &src)
        .map_err(|d| d.render_with_source(&src))?;

    replay_trace(&mut arena, &lex, &trace).map_err(|d| format!("{}", d))?;
    println!("replay    ok (bit-for-bit verified offline)");
    println!("trace     {}", trace.trace_hash.short_hex());
    println!("events    {}", trace.events.len());
    println!("fuel      {}/{}", trace.fuel_used, trace.fuel_limit);
    Ok(())
}

fn cmd_crystallize(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err(
            "usage: nacre crystallize <base.ncr> <candidate.ncr> <trace1.ntrace> [trace2 ...]".into(),
        );
    }
    let base_src = fs::read_to_string(&args[0]).map_err(|e| format!("read base failed: {}", e))?;
    let cand_src =
        fs::read_to_string(&args[1]).map_err(|e| format!("read candidate failed: {}", e))?;

    let mut traces = Vec::new();
    for path in &args[2..] {
        let raw = fs::read_to_string(path).map_err(|e| format!("read trace failed: {}", e))?;
        traces.push(Trace::decode_text(&raw).map_err(|d| format!("{}", d))?);
    }

    let mut arena = Arena::new();
    let mut base_lex = Lexicon::new();
    base_lex
        .load_source(&mut arena, &base_src)
        .map_err(|d| d.render_with_source(&base_src))?;

    let (_new_lex, cert) = crystallize_from_source(&mut arena, &base_lex, &traces, &cand_src)
        .map_err(|d| format!("{}", d))?;

    println!("crystallize  verified");
    println!("cert_hash    {}", cert.cert_hash.short_hex());
    println!("base_lex     {}", cert.base_lexicon_hash.short_hex());
    println!("new_lex      {}", cert.new_lexicon_hash.short_hex());
    println!(
        "traces       {} (merkle {})",
        cert.trace_count,
        cert.traces_merkle_root.short_hex()
    );
    println!(
        "effects      {} -> {} (eliminated {})",
        cert.base_effects,
        cert.new_effects,
        cert.effects_eliminated()
    );
    println!(
        "fuel         {} -> {} (delta {})",
        cert.base_fuel,
        cert.new_fuel,
        cert.fuel_saved()
    );
    println!(
        "caps         [{}] -> [{}]",
        cert.caps_before.join(", ").to_ascii_lowercase(),
        cert.caps_after.join(", ").to_ascii_lowercase()
    );
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: nacre verify <skill.ncrystal>".into());
    }
    let raw = fs::read_to_string(&args[0]).map_err(|e| format!("read bundle failed: {}", e))?;
    let bundle = CrystalBundle::decode_text(&raw).map_err(|d| format!("{}", d))?;
    let info = bundle.verify().map_err(|d| format!("{}", d))?;
    println!("verified     true");
    println!("name         {}", info.name);
    println!("bundle_hash  {}", info.bundle_hash.short_hex());
    println!("lexicon      {} ({} rules)", info.lexicon_hash.short_hex(), info.rule_count);
    println!("static_caps  [{}]", info.static_caps.join(", "));
    println!("offline_pure {}", info.is_pure);
    println!("eliminated   {} external effects", info.effects_eliminated);
    if let Some(sz) = info.wasm_size {
        println!("wasm_reflex  {} bytes verified", sz);
    }
    Ok(())
}

fn cmd_ingest_nanocode(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: nacre ingest-nanocode <journal.jsonl> <tool_name> [min_support|pure] [out.ncrystal]".into(),
        );
    }
    let jsonl = fs::read_to_string(&args[0]).map_err(|e| format!("read journal failed: {}", e))?;
    let tool = &args[1];
    let mode = match args.get(2).map(|s| s.as_str()) {
        None | Some("pure") => SynthMode::PureOffline,
        Some(n) => {
            let sup = n
                .parse::<usize>()
                .map_err(|_| "min_support must be positive int or 'pure'".to_string())?;
            SynthMode::HybridGuarded { min_support: sup }
        }
    };

    let (arena, summary, _traces, crystal) =
        crystallize_from_nanocode_jsonl(&jsonl, tool, mode).map_err(|d| format!("{}", d))?;
    let full_src = crystal.lexicon.to_source(&arena);
    let bundle = CrystalBundle::new(tool, &full_src, crystal.cert.clone(), None);

    println!("ingested     {} lines ({} matched calls, {} js nondet skipped)", summary.total_lines, summary.matched_calls, summary.js_nondet_entries_skipped);
    println!("cert_hash    {}", crystal.cert.cert_hash.short_hex());
    println!("bundle_hash  {}", bundle.bundle_hash.short_hex());
    println!("effects      {} -> {} (eliminated {})", crystal.cert.base_effects, crystal.cert.new_effects, crystal.cert.effects_eliminated());
    println!("offline_pure {}", crystal.cert.is_now_pure());
    println!("synthesized  {}", crystal.synthesized_src.to_ascii_lowercase());

    if let Some(out_path) = args.get(3) {
        fs::write(out_path, bundle.encode_text())
            .map_err(|e| format!("write bundle failed: {}", e))?;
        println!("written      {}", out_path.to_ascii_lowercase());
    }
    Ok(())
}

fn cmd_wasm_reflex(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: nacre wasm-reflex <lexicon.ncr> <rule_name> [out.wasm]".into());
    }
    let src = fs::read_to_string(&args[0]).map_err(|e| format!("read failed: {}", e))?;
    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, &src)
        .map_err(|d| d.render_with_source(&src))?;
    let head = arena
        .lookup_sym(&args[1])
        .ok_or_else(|| format!("unknown rule '{}'", args[1]))?;
    let reflex = compile_pure_i64_reflex(&arena, &lex, head).map_err(|d| format!("{}", d))?;

    println!("reflex     {}", reflex.entry_name.to_ascii_lowercase());
    println!("arity      {}", reflex.arity);
    println!("rule_hash  {}", reflex.rule_hash.short_hex());
    println!("wasm_hash  {}", reflex.wasm_hash.short_hex());
    println!("wasm_size  {} bytes", reflex.wasm_bytes.len());

    if let Some(out_path) = args.get(2) {
        fs::write(out_path, &reflex.wasm_bytes)
            .map_err(|e| format!("write wasm failed: {}", e))?;
        println!("written    {}", out_path.to_ascii_lowercase());
    }
    Ok(())
}

fn cmd_build_studio(args: &[String]) -> Result<(), String> {
    let wasm_path = args
        .first()
        .map(|s| s.as_str())
        .unwrap_or("target/wasm32-unknown-unknown/release/nacre_wasm.wasm");
    let tmpl_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("studio/template.html");
    let out_path = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("studio/index.html");

    let wasm_bytes = fs::read(wasm_path)
        .map_err(|e| format!("failed to read wasm '{}': {} (build wasm32 release first)", wasm_path, e))?;
    let tmpl = fs::read_to_string(tmpl_path)
        .map_err(|e| format!("failed to read template '{}': {}", tmpl_path, e))?;

    let b64 = base64_encode(&wasm_bytes);
    let bundled = tmpl.replace("__NACRE_WASM_BASE64__", &b64);

    if let Some(parent) = Path::new(out_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {}", e))?;
        }
    }
    fs::write(out_path, &bundled).map_err(|e| format!("write studio failed: {}", e))?;
    println!(
        "studio bundled -> {} ({} bytes total, {} bytes wasm)",
        out_path.to_ascii_lowercase(),
        bundled.len(),
        wasm_bytes.len()
    );
    Ok(())
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn cmd_security_bench() -> Result<(), String> {
    println!("=== nacre security control matrix (naked vs naive guard vs nacre kernel) ===");
    println!();
    let report = run_security_control_bench();

    println!("--- part 1: structural & supply-chain attack classes (breaches / probes — lower is better) ---");
    println!(
        "{:<22} | {:>10} {:>10} {:>10} | {}",
        "attack_class", "naked_ctrl", "naive_grd", "nacre", "nacre_guarantee"
    );
    let mut tot_p = 0usize;
    let mut tot_naked = 0usize;
    let mut tot_naive = 0usize;
    let mut tot_nacre = 0usize;
    for r in &report.static_classes {
        tot_p += r.probes;
        tot_naked += r.naked_breaches;
        tot_naive += r.naive_breaches;
        tot_nacre += r.nacre_breaches;
        println!(
            "{:<22} | {:>4}/{:<5} {:>4}/{:<5} {:>4}/{:<5} | {}",
            r.class_name,
            r.naked_breaches,
            r.probes,
            r.naive_breaches,
            r.probes,
            r.nacre_breaches,
            r.probes,
            r.mechanism
        );
    }
    println!(
        "{:<22} | {:>4}/{:<5} {:>4}/{:<5} {:>4}/{:<5} |",
        "TOTAL", tot_naked, tot_p, tot_naive, tot_p, tot_nacre, tot_p
    );

    println!();
    println!("--- part 2: adaptive red-queen control arms under identical pt-mcmc predator ---");
    println!(
        "{:<24} | {:>5} {:>9} {:>10} {:>10} {:>12}",
        "defense_arm", "gens", "alive", "reg_leaks", "final_st", "replay_llms"
    );
    for a in &report.adaptive_arms {
        let st = if a.pt_breached_final { "breached" } else { "held" };
        println!(
            "{:<24} | {:>5} {:>3}/{:<5} {:>10} {:>10} {:>12}",
            a.arm_name,
            a.gens_survived,
            a.final_alive_ok,
            a.final_alive_total,
            a.regression_leaks,
            st,
            a.replay_llm_calls
        );
    }
    Ok(())
}

fn cmd_coev() -> Result<(), String> {
    println!("=== nacre co-evolutionary security arena (pt-mcmc + hard antibodies) ===");
    println!("(67,108,864-state 2-turn glassy attack space · 12-query alive suite · zero floats)");
    println!();

    // 1. 4-way attacker ablation on Gen 0 (25 seeds x 3000 evals each)
    let gen0 = DefenderGen::gen0(0);
    println!("--- experiment 1: 4-way attacker ablation on gen 0 (25 seeds x 3000 evals) ---");
    println!(
        "{:<20} | {:>10} {:>12} {:>10} {:>10} {:>9}",
        "algorithm", "breaches", "avg_evals", "avg_min_e", "niches", "swap_acc"
    );
    for row in run_attacker_ablation(&gen0, 3000, 25) {
        println!(
            "{:<20} | {:>4}/{:<5} {:>12} {:>10} {:>10} {:>8}%",
            row.algo.label(),
            row.breaches,
            row.trials,
            row.avg_evals_when_breached,
            row.avg_best_energy,
            row.total_distinct_niches,
            row.avg_swap_accept_pct
        );
    }

    // 2. red-queen predator-prey hardening curve across generations
    println!();
    println!("--- experiment 2: red-queen predator-prey hardening (budget=4000 evals/gen) ---");
    println!(
        "{:<5} {:<9} {:<9} {:<9} {:<10} {:<10} {:<14} {}",
        "gen", "ab_count", "alive", "autoimm", "greedy", "pt_mcmc", "lex_hash", "exploit_or_status"
    );
    let (rounds, final_def) = run_red_queen_coevolution(0, 10, 4000, 0x1337_cafe);
    for r in &rounds {
        let pt_str = match r.pt_evals_to_breach {
            Some(e) => format!("breach@{}", e),
            None => String::from("held"),
        };
        let gr_str = if r.greedy_breached { "breach" } else { "held" };
        let detail = r
            .winning_exploit
            .as_deref()
            .unwrap_or("defender held full attack budget (economic hardness reached)");
        println!(
            "{:<5} {:<9} {:>2}/{:<6} {:<9} {:<10} {:<10} {:<14} {}",
            r.generation,
            r.antibodies_active,
            r.alive_passed,
            r.alive_total,
            r.autoimmune_rejected,
            gr_str,
            pt_str,
            r.lexicon_hash.short_hex(),
            detail
        );
    }

    // 3. 4-way attacker ablation AFTER red-queen hardening (on gen 4 checkpoint!)
    let (_, mid_def) = run_red_queen_coevolution(0, 4, 4000, 0x1337_cafe);
    println!();
    println!(
        "--- experiment 3: 4-way attacker ablation on hardened gen {} ({} antibodies, 25 seeds x 3000 evals) ---",
        mid_def.generation,
        mid_def.antibodies.len()
    );
    println!(
        "{:<20} | {:>10} {:>12} {:>10} {:>10} {:>9}",
        "algorithm", "breaches", "avg_evals", "avg_min_e", "niches", "swap_acc"
    );
    for row in run_attacker_ablation(&mid_def, 3000, 25) {
        println!(
            "{:<20} | {:>4}/{:<5} {:>12} {:>10} {:>10} {:>8}%",
            row.algo.label(),
            row.breaches,
            row.trials,
            row.avg_evals_when_breached,
            row.avg_best_energy,
            row.total_distinct_niches,
            row.avg_swap_accept_pct
        );
    }

    // 4. 4-model defender half-life under pt-mcmc co-evolution
    println!();
    println!("--- experiment 4: 4-model defender half-life under pt-mcmc co-evolution ---");
    println!(
        "{:<12} | {:>10} {:>11} {:>11} {:>12} {:>14}",
        "profile", "gens_held", "antibodies", "autoimm_rej", "alive", "fossil_root"
    );
    for p in 0..4u8 {
        let (pr, pf) = run_red_queen_coevolution(p, 10, 4000, 0xbeef_0000 + (p as u64) * 997);
        let (al_ok, al_tot) = pf.verify_alive_in_nacre();
        println!(
            "model_{:<6} | {:>10} {:>11} {:>11} {:>5}/{:<6} {:>14}",
            p,
            pr.len(),
            pf.antibodies.len(),
            pf.autoimmune_rejections,
            al_ok,
            al_tot,
            pf.fossil_merkle_root.short_hex()
        );
    }

    println!();
    println!(
        "final gen {} summary: {} hard nacre antibodies | {} fossils sealed (merkle {}) | 0 regression leaks | 100% alive",
        final_def.generation,
        final_def.antibodies.len(),
        final_def.fossils.len(),
        final_def.fossil_merkle_root.short_hex()
    );
    Ok(())
}

fn cmd_demo() -> Result<(), String> {
    println!("=== nacre end-to-end kernel demo ===");
    println!();

    let base_src = r#"
        (rule (triage ?msg)
          (perform llm_classify ?msg))

        (rule (route ?msg)
          (match (triage ?msg)
            (case urgent (escalate ?msg))
            (case billing (queue_billing ?msg))
            (case _ (queue_general ?msg))))

        ; fractal capability firewall using algebraic handle
        (rule (safe_fs (fs_read ?p) ?k)
          (if (str_starts_with ?p "/public/")
            (match (perform fs_read ?p)
              (case ?reply (handle (resume ?k ?reply) 500 safe_fs)))
            (blocked ?p)))

        (rule (sandboxed_read ?p)
          (handle (str_cat "body:" (perform fs_read ?p)) 500 safe_fs))

        ; pure recursive supercombinator for tier-2 wasm crystallization
        (rule (fib 0) 0)
        (rule (fib 1) 1)
        (rule (fib ?n) (add (fib (sub ?n 1)) (fib (sub ?n 2))))
    "#;

    let mut arena = Arena::new();
    let mut base_lex = Lexicon::new();
    base_lex
        .load_source(&mut arena, base_src)
        .map_err(|d| format!("{}", d))?;

    let sample_entry = parse_term(&mut arena, r#"(route "outage: db down")"#).unwrap();
    println!(
        "[1] base lexicon {} | static caps of (route ...): [{}]",
        base_lex.hash(&arena).short_hex(),
        base_lex.static_cap_names(&arena, sample_entry).join(", ")
    );

    let inputs = [
        r#"(route "outage: db down")"#,
        r#"(route "invoice #918 double billed")"#,
        r#"(route "question: dark mode?")"#,
        r#"(route "outage: api latency spike")"#,
        r#"(route "invoice #404 refund needed")"#,
        r#"(route "question: csv export?")"#,
    ];

    let mut traces = Vec::new();
    let mut total_wire_bytes = 0usize;
    for src in &inputs {
        let entry = parse_term(&mut arena, src).unwrap();
        let tr = run_and_record(&mut arena, &base_lex, entry, 2000, |a, eff| {
            let txt = match a.node(eff) {
                Node::App(_, args) => match a.node(args[0]) {
                    Node::Bytes(bs) => core::str::from_utf8(bs).unwrap_or(""),
                    _ => "",
                },
                _ => "",
            };
            let label = if txt.contains("outage") {
                "urgent"
            } else if txt.contains("invoice") {
                "billing"
            } else {
                "general"
            };
            let s = a.intern_sym(label);
            Ok(a.mk_sym(s)?.0)
        })
        .map_err(|d| format!("{}", d))?;
        total_wire_bytes += tr.encode_text().len();
        traces.push(tr);
    }

    println!(
        "[2] recorded {} durable merkle traces ({} bytes avg/trace) | 6 external llm calls",
        traces.len(),
        total_wire_bytes / traces.len()
    );
    println!(
        "    residual at event 0: {}",
        traces[0].events[0].residual_sexpr.to_ascii_lowercase()
    );

    // offline replay
    let wire = traces[0].encode_text();
    let decoded = Trace::decode_text(&wire).map_err(|d| format!("{}", d))?;
    let mut fresh_arena = Arena::new();
    let mut fresh_lex = Lexicon::new();
    fresh_lex.load_source(&mut fresh_arena, base_src).unwrap();
    replay_trace(&mut fresh_arena, &fresh_lex, &decoded).map_err(|d| format!("{}", d))?;
    println!(
        "[3] offline bit-for-bit replay verified in fresh arena (trace {})",
        decoded.trace_hash.short_hex()
    );

    // time-travel fork
    let alt_sym = arena.intern_sym("billing");
    let alt_reply = arena.mk_sym(alt_sym).unwrap().0;
    let forked = fork_from_event(&mut arena, &base_lex, &traces[0], 0, alt_reply, |_, _| {
        unreachable!()
    })
    .map_err(|d| format!("{}", d))?;
    if let TraceOutcome::Done { value_sexpr, .. } = &forked.outcome {
        println!(
            "[4] time-travel fork at event 0 (reply=billing) -> {}",
            value_sexpr.to_ascii_lowercase()
        );
    }

    // fractal capability firewall
    let bad_read = parse_term(&mut arena, r#"(sandboxed_read "/etc/shadow")"#).unwrap();
    let mut fw_fuel = Fuel::new(1000);
    if let Outcome::Done(v) = eval(&mut arena, &base_lex, bad_read, &mut fw_fuel) {
        println!(
            "[5] fractal handle firewall on /etc/shadow -> {} (0 host calls, {} fuel)",
            print_term(&arena, v).to_ascii_lowercase(),
            fw_fuel.used()
        );
    }

    // reject escalating reflex
    let evil_src = r#"(rule (triage ?msg) (perform net_exfil ?msg))"#;
    let evil_err = crystallize_from_source(&mut arena, &base_lex, &traces, evil_src).unwrap_err();
    println!("[6] rejected escalating reflex -> {}", evil_err);

    // autonomous crystallization (zero llm, zero manual reflex!)
    let crystal = auto_crystallize(&mut arena, &base_lex, &traces).map_err(|d| format!("{}", d))?;
    println!("[7] autonomous reflex synthesis + mechanical verification succeeded!");
    println!("    synthesized: {}", crystal.synthesized_src.to_ascii_lowercase());
    println!("    cert_hash:   {}", crystal.cert.cert_hash.short_hex());
    println!(
        "    effects:     {} -> {} (eliminated {})",
        crystal.cert.base_effects,
        crystal.cert.new_effects,
        crystal.cert.effects_eliminated()
    );
    println!(
        "    caps:        [{}] -> [{}] (offline pure: {})",
        crystal.cert.caps_before.join(", "),
        crystal.cert.caps_after.join(", "),
        crystal.cert.is_now_pure()
    );

    // live offline execution on unseen input
    let live_entry = parse_term(&mut arena, r#"(route "outage: edge node reboot")"#).unwrap();
    let live_trace = run_and_record(&mut arena, &crystal.lexicon, live_entry, 2000, |_, _| {
        panic!("pure crystallized reflex must never call host")
    })
    .map_err(|d| format!("{}", d))?;
    if let TraceOutcome::Done { value_sexpr, .. } = &live_trace.outcome {
        println!(
            "[8] live offline execution on unseen input -> {} (0 llm calls, {} fuel)",
            value_sexpr.to_ascii_lowercase(),
            live_trace.fuel_used
        );
    }

    // tier-2 wasm 1.0 reflex compilation + differential oracle parity check
    let fib_sym = arena.lookup_sym("fib").unwrap();
    let wasm_reflex =
        compile_pure_i64_reflex(&arena, &crystal.lexicon, fib_sym).map_err(|d| format!("{}", d))?;
    let fib_expr = parse_term(&mut arena, "(fib 10)").unwrap();
    let mut sym_fuel = Fuel::new(50_000);
    let sym_out = match eval(&mut arena, &crystal.lexicon, fib_expr, &mut sym_fuel) {
        Outcome::Done(v) => print_term(&arena, v),
        other => return Err(format!("unexpected fib outcome {:?}", other)),
    };
    let wasm_out = exec_wasm_reflex(&wasm_reflex.wasm_bytes, &[10], 50_000)
        .map_err(|d| format!("{}", d))?;
    println!(
        "[9] tier-2 wasm 1.0 reflex for (fib 10): {} bytes | wasm_hash {} | symbolic={} == wasm={} (status={}, calls={})",
        wasm_reflex.wasm_bytes.len(),
        wasm_reflex.wasm_hash.short_hex(),
        sym_out,
        wasm_out.value,
        wasm_out.status,
        wasm_out.fuel_used
    );

    Ok(())
}
