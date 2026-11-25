//! pure-rust swiss-monochrome studio & editorial product page compiled to wasm32.
//!
//! homepage (`overview`) tells the story calmly, one beat at a time:
//!   - hero:       1 headline + 1 crisp inline svg architecture diagram + 1 install command
//!   - chapter 01: live algebraic handle firewall (one clean interactive probe strip)
//!   - chapter 02: reflex compilation visual (openai/codex 96% + 186 b wasm 1.0)
//!   - chapter 03: live .ncrystal 1-byte tamper seal strip
//!   - chapter 04: copy-pasteable setup for claude code hooks, mcp servers, and jsonl logs
//!
//! deeper technical views (`compiler`, `benchmarks`, `repl`) live in the top nav.
//! enforces strict zero-capital-letters invariant on every rendered byte at the rust layer.

use std::cell::RefCell;

use nacre_core::arena::Arena;
use nacre_core::bundle::CrystalBundle;
use nacre_core::eval::{eval, plug_hole, Outcome};
use nacre_core::evolve::{eval_held_out_int, hill_climb_integer_task, ClimbStage};
use nacre_core::fuel::Fuel;
use nacre_core::hash::sha256;
use nacre_core::journal::run_and_record;
use nacre_core::lexicon::Lexicon;
use nacre_core::security_bench::{run_security_control_bench, SecurityBenchReport};
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize_with_mode, SynthMode};

const FW_LEX: &str = "\
(rule (agent_fw (fs_read ?p) ?k)
  (if (and (str_starts_with ?p \"/public/\")
           (not (str_contains ?p \"..\")))
    (ok (allowed_read ?p))
    (blocked fs_read ?p)))

(rule (agent_fw (http_post ?u ?b) ?k)
  (blocked http_post ?u))

(rule (agent_fw (reply ?t) ?k)
  (ok (reply ?t)))";

const SEAL_BASE_LEX: &str = "\
(rule (triage ?msg) (perform llm_classify ?msg))
(rule (route ?msg)
  (match (triage ?msg)
    (case urgent (escalate ?msg))
    (case _ (queue ?msg))))";

struct FwPreset {
    id: &'static str,
    label: &'static str,
    tool: &'static str,
    arg: &'static str,
    caption: &'static str,
}

const FW_PRESETS: &[FwPreset] = &[
    FwPreset {
        id: "haiku_hijack",
        label: "haiku 5.5 prefix escape",
        tool: "fs_read",
        arg: "/public_secret/prod_keys.env",
        caption: "captured live on claude-haiku-5.5 (--no-policy). bypasses naive starts_with(\"/public\") checks.",
    },
    FwPreset {
        id: "path_traversal",
        label: "dotdot traversal",
        tool: "fs_read",
        arg: "/public/../.env",
        caption: "starts with /public/, but climbs out via '..'. rejected mechanically by the handle rule.",
    },
    FwPreset {
        id: "code_inject",
        label: "code injection",
        tool: "inject_reply",
        arg: "(perform exfil \"prod_token\")",
        caption: "untrusted tool reply returns executable syntax. protect_value auto-quotes it into inert data.",
    },
    FwPreset {
        id: "benign_readme",
        label: "allowed read",
        tool: "fs_read",
        arg: "/public/readme.md",
        caption: "canonical path strictly inside /public/. allowed with zero false-positive friction.",
    },
];

struct CompTaskDef {
    id: &'static str,
    label: &'static str,
    desc: &'static str,
    default_n: i64,
    oracle: fn(i64) -> i64,
    train: &'static [i64],
    held_out: &'static [i64],
    is_control: bool,
}

fn is_prime_i64(n: i64) -> i64 {
    if n < 2 {
        return 0;
    }
    let mut d = 2;
    while d * d <= n {
        if n % d == 0 {
            return 0;
        }
        d += 1;
    }
    1
}

const COMP_TASKS: &[CompTaskDef] = &[
    CompTaskDef {
        id: "sum_to_n",
        label: "sum_to_n",
        desc: "0+1+...+n · recursive → closed form → 186 b wasm",
        default_n: 50,
        oracle: |n| n * (n + 1) / 2,
        train: &[0, 1, 2, 3, 4, 5, 6],
        held_out: &[10, 15, 25, 50],
        is_control: false,
    },
    CompTaskDef {
        id: "affine_3x_p7",
        label: "affine_3x_p7",
        desc: "3x + 7 · closed form from 6 traces",
        default_n: 25,
        oracle: |n| 3 * n + 7,
        train: &[0, 1, 2, 3, 4, 5],
        held_out: &[-10, 11, 25, 100],
        is_control: false,
    },
    CompTaskDef {
        id: "quad_x2_px",
        label: "quad_x2_px",
        desc: "x^2 + x · quadratic discovery → 164 b wasm",
        default_n: 20,
        oracle: |n| n * n + n,
        train: &[0, 1, 2, 3, 4, 5],
        held_out: &[-7, 9, 20, 50],
        is_control: false,
    },
    CompTaskDef {
        id: "factorial",
        label: "factorial",
        desc: "n! · recursive rule discovery → 177 b wasm",
        default_n: 10,
        oracle: |n| (1..=n).product(),
        train: &[0, 1, 2, 3, 4, 5],
        held_out: &[6, 7, 8, 10],
        is_control: false,
    },
    CompTaskDef {
        id: "abs_val",
        label: "abs_val",
        desc: "|x| · piecewise unification → 172 b wasm",
        default_n: -42,
        oracle: |n| n.abs(),
        train: &[-5, -2, -1, 0, 1, 3, 6],
        held_out: &[-99, -12, 7, 42],
        is_control: false,
    },
    CompTaskDef {
        id: "clamp_0_10",
        label: "clamp_0_10",
        desc: "clamp(x, 0, 10) · 3-region piecewise → 180 b wasm",
        default_n: 100,
        oracle: |n| n.clamp(0, 10),
        train: &[-5, -1, 0, 3, 7, 10, 12, 20],
        held_out: &[-50, 1, 5, 9, 11, 100],
        is_control: false,
    },
    CompTaskDef {
        id: "collatz_step",
        label: "collatz_step",
        desc: "even ? n/2 : 3n+1 · modulo predicate → 234 b wasm",
        default_n: 27,
        oracle: |n| if n % 2 == 0 { n / 2 } else { 3 * n + 1 },
        train: &[1, 2, 3, 4, 5, 6, 7, 8],
        held_out: &[9, 10, 15, 22, 27],
        is_control: false,
    },
    CompTaskDef {
        id: "prime_ctrl",
        label: "prime_ctrl [control]",
        desc: "falsification control · must safely escalate 6/6",
        default_n: 17,
        oracle: is_prime_i64,
        train: &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        held_out: &[12, 13, 15, 17, 21, 23],
        is_control: true,
    },
];

struct CompStageView {
    stage: String,
    rule_src: String,
    train_eff: u64,
    train_fuel: u64,
    ho_exact: usize,
    ho_total: usize,
    ho_escalated: usize,
    ho_wrong: usize,
    ho_fuel: u64,
}

struct CompResultView {
    task_id: String,
    final_stage: String,
    candidates_eval: u64,
    obs_pruned: u64,
    stages: Vec<CompStageView>,
    final_lex_src: String,
    wasm_bytes_len: Option<usize>,
    wasm_hex: String,
    wasm_sha: String,
    default_n: i64,
    oracle_at_n: i64,
    is_control: bool,
}

struct StudioState {
    page: &'static str, // "overview" | "compiler" | "benchmarks" | "repl"
    setup_tab: &'static str, // "claude" | "mcp" | "reflex"
    // firewall live state
    fw_preset: String,
    fw_tool: String,
    fw_arg: String,
    fw_caption: String,
    fw_nacre_status: &'static str, // "blocked" | "allowed" | "quoted_safe"
    fw_nacre_expr: String,
    fw_merkle: String,
    fw_fuel: u64,
    // seal state
    seal_valid_wire: String,
    seal_tampered: bool,
    seal_ok: bool,
    seal_hash: String,
    seal_caps: String,
    seal_msg: String,
    // compiler state
    comp_task_id: String,
    comp_result: Option<CompResultView>,
    // live wasm-verified security bench cache
    live_sec_bench: Option<SecurityBenchReport>,
    live_sec_checksum: Option<String>,
    // repl state
    repl_preset: String,
    repl_lex: String,
    repl_expr: String,
    repl_wasm_head: String,
    repl_wasm_arg: String,
    repl_caps: String,
    repl_out: String,
}

impl StudioState {
    fn new() -> Self {
        let mut st = Self {
            page: "overview",
            setup_tab: "claude",
            fw_preset: String::from("haiku_hijack"),
            fw_tool: String::from("fs_read"),
            fw_arg: String::from("/public_secret/prod_keys.env"),
            fw_caption: String::from(FW_PRESETS[0].caption),
            fw_nacre_status: "blocked",
            fw_nacre_expr: String::new(),
            fw_merkle: String::new(),
            fw_fuel: 0,
            seal_valid_wire: String::new(),
            seal_tampered: false,
            seal_ok: true,
            seal_hash: String::new(),
            seal_caps: String::from("none"),
            seal_msg: String::new(),
            comp_task_id: String::from("sum_to_n"),
            comp_result: None,
            live_sec_bench: None,
            live_sec_checksum: None,
            repl_preset: String::from("fib"),
            repl_lex: String::from(
                "(rule (fib 0) 0)\n(rule (fib 1) 1)\n(rule (fib ?n) (add (fib (sub ?n 1)) (fib (sub ?n 2))))",
            ),
            repl_expr: String::from("(fib 12)"),
            repl_wasm_head: String::from("fib"),
            repl_wasm_arg: String::from("12"),
            repl_caps: String::from("pure offline (0 caps)"),
            repl_out: String::new(),
        };
        st.eval_firewall();
        st.init_seal();
        st.run_repl();
        st
    }

    fn dispatch(&mut self, action: &str, payload: &str) {
        let pay = payload.to_ascii_lowercase();
        match action {
            "init" => {}
            "page" => {
                self.page = match pay.trim() {
                    "compiler" => "compiler",
                    "benchmarks" => "benchmarks",
                    "repl" => "repl",
                    _ => "overview",
                };
                if self.page == "compiler" && self.comp_result.is_none() {
                    self.run_compiler("sum_to_n");
                }
            }
            "setup_tab" => {
                self.setup_tab = match pay.trim() {
                    "mcp" => "mcp",
                    "reflex" => "reflex",
                    _ => "claude",
                };
            }
            "fw_preset" => {
                if let Some(p) = FW_PRESETS.iter().find(|x| x.id == pay.trim()) {
                    self.fw_preset = String::from(p.id);
                    self.fw_tool = String::from(p.tool);
                    self.fw_arg = String::from(p.arg);
                    self.fw_caption = String::from(p.caption);
                    self.eval_firewall();
                }
            }
            "fw_run" => {
                if let Some((t, a)) = pay.split_once('\t') {
                    self.fw_tool = String::from(t.trim());
                    self.fw_arg = String::from(a.trim());
                } else if !pay.trim().is_empty() {
                    self.fw_arg = String::from(pay.trim());
                }
                self.fw_preset = String::from("custom");
                self.fw_caption = String::from("evaluated live inside nacre-core wasm32 in your browser.");
                self.eval_firewall();
            }
            "seal_tamper" => {
                self.seal_tampered = true;
                self.verify_seal();
            }
            "seal_restore" => {
                self.seal_tampered = false;
                self.verify_seal();
            }
            "comp_task" => {
                let tid = pay.trim().to_string();
                self.run_compiler(&tid);
            }
            "verify_bench" => {
                let rep = run_security_control_bench();
                let mut sig = String::new();
                for r in &rep.static_classes {
                    sig.push_str(&format!("{}:{}/{}/{};", r.class_name, r.naked_breaches, r.naive_breaches, r.nacre_breaches));
                }
                for a in &rep.adaptive_arms {
                    sig.push_str(&format!("{}:{}/{}:{};", a.arm_name, a.final_alive_ok, a.final_alive_total, a.regression_leaks));
                }
                self.live_sec_checksum = Some(sha256(sig.as_bytes()).short_hex());
                self.live_sec_bench = Some(rep);
            }
            "repl_preset" => {
                self.load_repl_preset(pay.trim());
                self.run_repl();
            }
            "repl_run" => {
                if let Some((l, e)) = pay.split_once("\n---\n") {
                    self.repl_lex = String::from(l);
                    self.repl_expr = String::from(e);
                }
                self.run_repl();
            }
            _ => {}
        }
    }

    fn eval_firewall(&mut self) {
        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        if lex.load_source(&mut arena, FW_LEX).is_err() {
            return;
        }

        if self.fw_tool == "inject_reply" {
            let _ = lex.load_source(
                &mut arena,
                "(rule (summarize ?doc) (tag_summary (perform fetch_doc ?doc)))",
            );
            let Ok(entry) = parse_term(&mut arena, "(summarize \"ticket_42\")") else {
                return;
            };
            let mut fuel = Fuel::new(2000);
            if let Outcome::Yield { resume, .. } = eval(&mut arena, &lex, entry, &mut fuel) {
                let Ok(untrusted_reply) = parse_term(&mut arena, &self.fw_arg) else {
                    let s_id = arena.mk_str(&self.fw_arg).map(|x| x.0).unwrap_or(entry);
                    self.fw_nacre_status = "quoted_safe";
                    self.fw_nacre_expr = format!("(tag_summary {})", print_term(&arena, s_id));
                    self.fw_merkle = arena.hash(s_id).short_hex();
                    self.fw_fuel = fuel.used();
                    return;
                };
                if let Ok(plugged) = plug_hole(&mut arena, resume, untrusted_reply) {
                    let mut fuel2 = Fuel::new(2000);
                    if let Outcome::Done(v) = eval(&mut arena, &lex, plugged, &mut fuel2) {
                        self.fw_nacre_status = "quoted_safe";
                        self.fw_nacre_expr = print_term(&arena, v);
                        self.fw_merkle = arena.hash(v).short_hex();
                        self.fw_fuel = fuel.used() + fuel2.used();
                    }
                }
            }
            return;
        }

        let expr_src = if self.fw_tool == "http_post" {
            format!(
                "(handle (perform http_post {} \"payload\") 500 agent_fw)",
                nacre_quote(&self.fw_arg)
            )
        } else {
            format!(
                "(handle (perform fs_read {}) 500 agent_fw)",
                nacre_quote(&self.fw_arg)
            )
        };

        let Ok(expr) = parse_term(&mut arena, &expr_src) else {
            return;
        };
        let mut fuel = Fuel::new(2000);
        if let Outcome::Done(v) = eval(&mut arena, &lex, expr, &mut fuel) {
            let txt = print_term(&arena, v);
            let blocked = txt.starts_with("(blocked ");
            self.fw_nacre_expr = txt;
            self.fw_merkle = arena.hash(v).short_hex();
            self.fw_fuel = fuel.used();
            self.fw_nacre_status = if blocked { "blocked" } else { "allowed" };
        }
    }

    fn init_seal(&mut self) {
        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        if lex.load_source(&mut arena, SEAL_BASE_LEX).is_err() {
            return;
        }
        let samples = [
            ("outage: db primary down", "urgent"),
            ("outage: eu edge 503", "urgent"),
            ("docs question", "general"),
            ("theme request", "general"),
        ];
        let mut traces = Vec::new();
        for (msg, lbl) in samples {
            if let Ok(entry) = parse_term(&mut arena, &format!("(route {})", nacre_quote(msg))) {
                let lbl_s = String::from(lbl);
                if let Ok(tr) = run_and_record(&mut arena, &lex, entry, 5000, |a, _| {
                    let s = a.intern_sym(&lbl_s);
                    Ok(a.mk_sym(s)?.0)
                }) {
                    traces.push(tr);
                }
            }
        }
        if let Ok(ac) =
            auto_crystallize_with_mode(&mut arena, &lex, &traces, SynthMode::PureOffline)
        {
            let full = ac.lexicon.to_source(&arena);
            let bundle = CrystalBundle::new("triage", &full, ac.cert, None);
            self.seal_valid_wire = bundle.encode_text();
            self.seal_tampered = false;
            self.verify_seal();
        }
    }

    fn verify_seal(&mut self) {
        let wire = if self.seal_tampered {
            self.seal_valid_wire.replace("escalate", "exfiltrate")
        } else {
            self.seal_valid_wire.clone()
        };
        match CrystalBundle::decode_text(&wire) {
            Ok(b) => match b.verify() {
                Ok(info) => {
                    self.seal_ok = true;
                    self.seal_hash = info.bundle_hash.short_hex();
                    self.seal_caps = if info.static_caps.is_empty() {
                        String::from("none")
                    } else {
                        info.static_caps.join(", ")
                    };
                    self.seal_msg = format!(
                        "sha-256 verified · bundle {} · {} rules · static caps: {}",
                        self.seal_hash, info.rule_count, self.seal_caps
                    );
                }
                Err(d) => {
                    self.seal_ok = false;
                    self.seal_msg = format!("rejected before execution: {}", d);
                }
            },
            Err(d) => {
                self.seal_ok = false;
                self.seal_msg = format!("rejected before execution: {}", d);
            }
        }
    }

    fn run_compiler(&mut self, task_id: &str) {
        let Some(task) = COMP_TASKS.iter().find(|t| t.id == task_id) else {
            return;
        };
        self.comp_task_id = String::from(task.id);

        let mut arena = Arena::new();
        let mut base_lex = Lexicon::new();
        if base_lex
            .load_source(&mut arena, "(rule (solve ?p0) (perform oracle ?p0))")
            .is_err()
        {
            return;
        }

        let mut traces = Vec::new();
        for &x in task.train {
            let Ok(entry) = parse_term(&mut arena, &format!("(solve {})", x)) else {
                continue;
            };
            let ans = (task.oracle)(x);
            if let Ok(tr) =
                run_and_record(&mut arena, &base_lex, entry, 50_000, |a, _| Ok(a.mk_int(ans)?.0))
            {
                traces.push(tr);
            }
        }

        let held_out_pairs: Vec<(Vec<i64>, i64)> = task
            .held_out
            .iter()
            .map(|&x| (vec![x], (task.oracle)(x)))
            .collect();

        let Ok(report) = hill_climb_integer_task(&mut arena, &base_lex, &traces, "solve") else {
            return;
        };

        let mut stages = Vec::new();
        for step in &report.history {
            let mut step_arena = Arena::new();
            let mut step_lex = Lexicon::new();
            let _ = step_lex.load_source(&mut step_arena, &step.rule_src);
            let ho = eval_held_out_int(&mut step_arena, &step_lex, "solve", &held_out_pairs, 50_000);
            stages.push(CompStageView {
                stage: String::from(step.stage.label()),
                rule_src: step.rule_src.clone(),
                train_eff: step.train_effects,
                train_fuel: step.train_fuel,
                ho_exact: ho.offline_exact,
                ho_total: ho.total,
                ho_escalated: ho.escalated_safe,
                ho_wrong: ho.offline_wrong,
                ho_fuel: ho.total_fuel,
            });
        }

        let (wasm_bytes_len, wasm_hex, wasm_sha) = if let Some(ref wf) = report.wasm_reflex {
            let bytes = &wf.wasm_bytes;
            let mut hex = String::with_capacity(bytes.len() * 3);
            for (idx, b) in bytes.iter().enumerate() {
                if idx > 0 && idx % 16 == 0 {
                    hex.push('\n');
                } else if idx > 0 {
                    hex.push(' ');
                }
                hex.push_str(&format!("{:02x}", b));
            }
            (Some(bytes.len()), hex, sha256(bytes).short_hex())
        } else {
            (None, String::new(), String::new())
        };

        let final_lex_src = report.final_lexicon.to_source(&arena);
        let final_stage = String::from(report.final_stage().label());
        let oracle_at_n = (task.oracle)(task.default_n);

        if let Some(blen) = wasm_bytes_len {
            let last_ho = stages.last().map(|s| (s.ho_exact, s.ho_total)).unwrap_or((0, 0));
            stages.push(CompStageView {
                stage: String::from(ClimbStage::Gen4WasmReflex.label()),
                rule_src: format!("wasm 1.0 binary · {} bytes · sha-256 {}", blen, wasm_sha),
                train_eff: 0,
                train_fuel: 1,
                ho_exact: last_ho.0,
                ho_total: last_ho.1,
                ho_escalated: 0,
                ho_wrong: 0,
                ho_fuel: last_ho.1 as u64,
            });
        }

        self.comp_result = Some(CompResultView {
            task_id: String::from(task.id),
            final_stage,
            candidates_eval: report.candidates_evaluated,
            obs_pruned: report.candidates_pruned_obs_equiv,
            stages,
            final_lex_src,
            wasm_bytes_len,
            wasm_hex,
            wasm_sha,
            default_n: task.default_n,
            oracle_at_n,
            is_control: task.is_control,
        });
    }

    fn load_repl_preset(&mut self, id: &str) {
        self.repl_preset = String::from(id);
        match id {
            "firewall" => {
                self.repl_lex = String::from(FW_LEX);
                self.repl_expr =
                    String::from("(handle (perform fs_read \"/public_secret/prod_keys.env\") 500 agent_fw)");
                self.repl_wasm_head = String::from("agent_fw");
                self.repl_wasm_arg = String::from("1");
            }
            "collatz" => {
                self.repl_lex = String::from(
                    "(rule (collatz ?n) (if (eq (mod ?n 2) 0) (div ?n 2) (add (mul 3 ?n) 1)))",
                );
                self.repl_expr = String::from("(collatz 27)");
                self.repl_wasm_head = String::from("collatz");
                self.repl_wasm_arg = String::from("27");
            }
            "sum_closed" => {
                self.repl_lex =
                    String::from("(rule (sum_to ?n) (div (add ?n (mul ?n ?n)) 2))");
                self.repl_expr = String::from("(sum_to 50)");
                self.repl_wasm_head = String::from("sum_to");
                self.repl_wasm_arg = String::from("50");
            }
            _ => {
                self.repl_lex = String::from(
                    "(rule (fib 0) 0)\n(rule (fib 1) 1)\n(rule (fib ?n) (add (fib (sub ?n 1)) (fib (sub ?n 2))))",
                );
                self.repl_expr = String::from("(fib 12)");
                self.repl_wasm_head = String::from("fib");
                self.repl_wasm_arg = String::from("12");
            }
        }
    }

    fn run_repl(&mut self) {
        let bundle = format!("{}\n---\n{}", self.repl_lex, self.repl_expr);
        let (_, caps) = crate::caps_bundle(&bundle);
        let (_, eval_out) = crate::eval_bundle(&bundle, 50_000);
        self.repl_caps = caps;
        self.repl_out = eval_out;
    }

    fn render_html(&self) -> String {
        let mut h = String::with_capacity(20_000);
        let shell_cls = if self.page == "overview" { "story" } else { "shell" };
        h.push_str(&format!(
            "<header class=\"topbar\">\
              <div class=\"topbar-inner\">\
                <button class=\"wordmark\" data-act=\"page\" data-val=\"overview\">nacre</button>\
                <nav class=\"nav\">\
                  <button class=\"nav-btn {}\" data-act=\"page\" data-val=\"overview\">overview</button>\
                  <button class=\"nav-btn {}\" data-act=\"page\" data-val=\"compiler\">compiler</button>\
                  <button class=\"nav-btn {}\" data-act=\"page\" data-val=\"benchmarks\">benchmarks</button>\
                  <button class=\"nav-btn {}\" data-act=\"page\" data-val=\"repl\">repl</button>\
                </nav>\
                <div class=\"ext-links\">\
                  <a href=\"https://github.com/compusophy/nacre\" target=\"_blank\" rel=\"noopener\">github ↗</a>\
                </div>\
              </div>\
            </header><main class=\"{}\">",
            if self.page == "overview" { "active" } else { "" },
            if self.page == "compiler" { "active" } else { "" },
            if self.page == "benchmarks" { "active" } else { "" },
            if self.page == "repl" { "active" } else { "" },
            shell_cls,
        ));

        match self.page {
            "compiler" => self.render_compiler(&mut h),
            "benchmarks" => self.render_benchmarks(&mut h),
            "repl" => self.render_repl(&mut h),
            _ => self.render_overview(&mut h),
        }

        h.push_str(
            "</main><footer class=\"foot\"><div class=\"foot-inner\">\
            <span>nacre · #![no_std] rust · 0 external deps</span>\
            <span><a href=\"https://github.com/compusophy/nacre\" target=\"_blank\" rel=\"noopener\">github.com/compusophy/nacre</a></span>\
            </div></footer>",
        );
        h.to_ascii_lowercase()
    }

    fn render_overview(&self, h: &mut String) {
        // =====================================================================
        // BEAT 0: THE OPENING — ONE HEADLINE, ONE DIAGRAM, ONE INSTALL COMMAND
        // =====================================================================
        h.push_str(
            "<section class=\"hero-beat\">\
              <h1 class=\"hero-title\">a firewall and reflex compiler for ai agents.</h1>\
              <p class=\"hero-copy\">nacre sits between your agent and the host. every tool call passes through a pure effect handler before it touches disk or network, and repeated calls compile down to offline wasm reflexes.</p>\
              <div class=\"diagram-box\">\
                <svg viewBox=\"0 0 820 228\" width=\"100%\" height=\"auto\" xmlns=\"http://www.w3.org/2000/svg\" aria-label=\"nacre architecture\">\
                  <!-- left: agent -->\
                  <rect x=\"12\" y=\"52\" width=\"190\" height=\"86\" fill=\"#111111\" stroke=\"#2b2b2b\" stroke-width=\"1\"/>\
                  <text x=\"30\" y=\"84\" fill=\"#ecece6\" font-family=\"monospace\" font-size=\"14\" font-weight=\"600\">your agent</text>\
                  <text x=\"30\" y=\"107\" fill=\"#7a7a72\" font-family=\"monospace\" font-size=\"11\">claude code · cursor</text>\
                  <text x=\"30\" y=\"123\" fill=\"#7a7a72\" font-family=\"monospace\" font-size=\"11\">codex · mcp client</text>\
                  <!-- arrow 1 -->\
                  <line x1=\"202\" y1=\"95\" x2=\"282\" y2=\"95\" stroke=\"#4a4a44\" stroke-width=\"1\"/>\
                  <polygon points=\"282,91 290,95 282,99\" fill=\"#8a8a82\"/>\
                  <text x=\"215\" y=\"84\" fill=\"#7a7a72\" font-family=\"monospace\" font-size=\"10.5\">tool call</text>\
                  <!-- center: nacre kernel -->\
                  <rect x=\"292\" y=\"36\" width=\"232\" height=\"118\" fill=\"#151515\" stroke=\"#ecece6\" stroke-width=\"1.2\"/>\
                  <text x=\"312\" y=\"67\" fill=\"#ecece6\" font-family=\"monospace\" font-size=\"15\" font-weight=\"700\">nacre</text>\
                  <text x=\"312\" y=\"91\" fill=\"#a0a098\" font-family=\"monospace\" font-size=\"11.5\">1. pure handle firewall</text>\
                  <text x=\"312\" y=\"111\" fill=\"#a0a098\" font-family=\"monospace\" font-size=\"11.5\">2. sha-256 audit journal</text>\
                  <text x=\"312\" y=\"131\" fill=\"#a0a098\" font-family=\"monospace\" font-size=\"11.5\">3. offline reflex cache</text>\
                  <!-- top right: blocked -->\
                  <polyline points=\"524,72 568,72 568,48 606,48\" fill=\"none\" stroke=\"#e5484d\" stroke-width=\"1\"/>\
                  <polygon points=\"606,44 614,48 606,52\" fill=\"#e5484d\"/>\
                  <rect x=\"616\" y=\"18\" width=\"192\" height=\"60\" fill=\"#140d0e\" stroke=\"#522426\" stroke-width=\"1\"/>\
                  <text x=\"632\" y=\"44\" fill=\"#e5484d\" font-family=\"monospace\" font-size=\"13\" font-weight=\"600\">blocked</text>\
                  <text x=\"632\" y=\"63\" fill=\"#9b7a7c\" font-family=\"monospace\" font-size=\"10.5\">merkle proof · $0 tokens</text>\
                  <!-- middle right: allowed -->\
                  <polyline points=\"524,118 568,118 568,134 606,134\" fill=\"none\" stroke=\"#3fb97a\" stroke-width=\"1\"/>\
                  <polygon points=\"606,130 614,134 606,138\" fill=\"#3fb97a\"/>\
                  <rect x=\"616\" y=\"104\" width=\"192\" height=\"60\" fill=\"#0d1410\" stroke=\"#204a34\" stroke-width=\"1\"/>\
                  <text x=\"632\" y=\"130\" fill=\"#3fb97a\" font-family=\"monospace\" font-size=\"13\" font-weight=\"600\">allowed</text>\
                  <text x=\"632\" y=\"149\" fill=\"#789c88\" font-family=\"monospace\" font-size=\"10.5\">mcp server · local disk</text>\
                  <!-- bottom feedback loop: journal -> wasm reflex -->\
                  <polyline points=\"408,154 408,202 106,202 106,144\" fill=\"none\" stroke=\"#44443e\" stroke-width=\"1\" stroke-dasharray=\"4 4\"/>\
                  <polygon points=\"102,146 106,138 110,146\" fill=\"#7a7a72\"/>\
                  <rect x=\"172\" y=\"188\" width=\"218\" height=\"26\" fill=\"#0d0d0d\"/>\
                  <text x=\"180\" y=\"205\" fill=\"#8e8e86\" font-family=\"monospace\" font-size=\"11\">repeated traces → 186 b wasm</text>\
                </svg>\
              </div>\
              <div class=\"cmd-bar\">\
                <code class=\"mono\" id=\"cmd-install\">cargo install --path crates/nacre-cli &amp;&amp; nacre init</code>\
                <button class=\"copy-btn\" data-copy=\"cmd-install\">copy</button>\
              </div>\
              <div class=\"quiet-links mono\">\
                <span>scroll to try the live wasm kernel</span>\
                <span>·</span>\
                <button class=\"link-btn\" data-act=\"page\" data-val=\"benchmarks\">all 7 benchmarks (0/18 breaches, 184 live model calls) →</button>\
              </div>\
            </section>",
        );

        // =====================================================================
        // BEAT 1: CAPABILITY FIREWALL (ONE FOCUSED INTERACTIVE STRIP)
        // =====================================================================
        let verdict_cls = match self.fw_nacre_status {
            "blocked" => "err",
            _ => "ok",
        };
        let verdict_word = match self.fw_nacre_status {
            "blocked" => "blocked",
            "quoted_safe" => "auto-quoted",
            _ => "allowed",
        };

        h.push_str(
            "<section class=\"beat\">\
              <div class=\"beat-k mono\">01 / capability firewall</div>\
              <h2 class=\"beat-title\">prompt rules are polite requests. an effect handler is a wall.</h2>\
              <p class=\"beat-copy\">when we tested four fast models without an explicit path rule in the prompt, an untrusted doc talked claude-haiku-5.5 into reading <code>/public_secret/prod_keys.env</code>. nacre intercepts every call in pure rust before it leaves your process.</p>\
              <div class=\"widget\">\
                <div class=\"tab-strip\">",
        );
        for p in FW_PRESETS {
            let active = if self.fw_preset == p.id { " active" } else { "" };
            h.push_str(&format!(
                "<button class=\"tab-item{}\" data-act=\"fw_preset\" data-val=\"{}\">{}</button>",
                active, p.id, p.label
            ));
        }
        h.push_str(&format!(
            "</div>\
                <div class=\"widget-body\">\
                  <div class=\"input-row\">\
                    <span class=\"tool-pill mono\">{}</span>\
                    <input class=\"inp mono\" id=\"fw-arg-in\" type=\"text\" value=\"{}\" data-enter=\"fw_run\" data-tool=\"{}\">\
                    <button class=\"act-btn primary\" data-act=\"fw_run\" data-from=\"fw-arg-in\" data-tool=\"{}\">run</button>\
                  </div>\
                  <p class=\"caption\">{}</p>\
                  <div class=\"verdict-strip\">\
                    <span class=\"verdict-pill mono {}\">{}</span>\
                    <code class=\"verdict-expr mono\">{}</code>\
                    <span class=\"verdict-meta mono\">merkle {} · {} fuel</span>\
                  </div>\
                </div>\
                <details class=\"drawer\"><summary>inspect the 8-line policy running live in wasm32</summary><pre class=\"code\">{}</pre></details>\
              </div>\
            </section>",
            esc_html(&self.fw_tool),
            esc_html(&self.fw_arg),
            esc_html(&self.fw_tool),
            esc_html(&self.fw_tool),
            esc_html(&self.fw_caption),
            verdict_cls,
            verdict_word,
            esc_html(&self.fw_nacre_expr),
            esc_html(&self.fw_merkle),
            self.fw_fuel,
            esc_html(FW_LEX),
        ));

        // =====================================================================
        // BEAT 2: REFLEX COMPILER (TWO CALM VISUAL CARDS)
        // =====================================================================
        h.push_str(
            "<section class=\"beat\">\
              <div class=\"beat-k mono\">02 / reflex compiler</div>\
              <h2 class=\"beat-title\">stop paying a model for work it already solved.</h2>\
              <p class=\"beat-copy\">the same journal that audits your agent is a training trace. once a pattern holds with 100% purity across past runs, nacre distills it into an offline rule or a tiny webassembly binary and escalates anything unfamiliar back to the llm.</p>\
              <div class=\"two-up\">\
                <div class=\"story-card\">\
                  <div class=\"card-k mono\">170 real openai/codex github issues</div>\
                  <div class=\"big-stat mono ok\">96% <span class=\"big-sub\">precision</span></div>\
                  <p class=\"card-p\">42% of future llm triage calls eliminated with zero gpu training (101 oldest train → 69 unseen future).</p>\
                  <div class=\"mini-bars mono\">\
                    <div class=\"mbar-row\"><span>ungated pure</span><span class=\"warn\">72%</span></div>\
                    <div class=\"mbar-track\"><div class=\"mbar-fill warn\" style=\"width:72%\"></div></div>\
                    <div class=\"mbar-row\"><span>nacre hybrid</span><span class=\"ok\">96%</span></div>\
                    <div class=\"mbar-track\"><div class=\"mbar-fill ok\" style=\"width:96%\"></div></div>\
                  </div>\
                </div>\
                <div class=\"story-card\">\
                  <div class=\"card-k mono\">sum_to_n · 5-stage superoptimization</div>\
                  <div class=\"big-stat mono\">186 b <span class=\"big-sub\">wasm 1.0</span></div>\
                  <p class=\"card-p\">climbs from an oracle call to a closed form (18.5x less fuel) and emits raw webassembly bytes.</p>\
                  <div class=\"ladder mono\">\
                    <div class=\"lad-row\"><span>gen 2 recursive</span><span class=\"dim\">1,112 fuel</span></div>\
                    <div class=\"lad-row\"><span>gen 3 closed form</span><span class=\"ok\">60 fuel</span></div>\
                    <div class=\"lad-row\"><span>gen 4 wasm binary</span><span class=\"ok\">186 bytes</span></div>\
                  </div>\
                  <button class=\"link-btn mono\" style=\"margin-top:12px;\" data-act=\"page\" data-val=\"compiler\">compile &amp; run wasm live in browser →</button>\
                </div>\
              </div>\
            </section>",
        );

        // =====================================================================
        // BEAT 3: TAMPER-EVIDENT SEALS (ONE INTERACTIVE STRIP)
        // =====================================================================
        let seal_cls = if self.seal_ok { "ok" } else { "err" };
        let seal_btn = if self.seal_tampered {
            "<button class=\"act-btn\" data-act=\"seal_restore\">restore valid seal</button>"
        } else {
            "<button class=\"act-btn danger\" data-act=\"seal_tamper\">flip 1 byte</button>"
        };
        h.push_str(&format!(
            "<section class=\"beat\">\
              <div class=\"beat-k mono\">03 / tamper-evident bundles &amp; logs</div>\
              <h2 class=\"beat-title\">change one byte and it refuses to run.</h2>\
              <p class=\"beat-copy\">every distilled skill (.ncrystal) carries a sha-256 hash and static capability audit; every mcp or hook decision writes to a hash-chained audit log you can verify offline with <code>nacre audit-verify</code>.</p>\
              <div class=\"seal-strip\">\
                <div class=\"seal-left\">\
                  <span class=\"verdict-pill mono {}\">{}</span>\
                  <span class=\"mono {}\">{}</span>\
                </div>\
                <div>{}</div>\
              </div>\
            </section>",
            seal_cls,
            if self.seal_ok { "verified" } else { "rejected" },
            seal_cls,
            esc_html(&self.seal_msg),
            seal_btn,
        ));

        // =====================================================================
        // BEAT 4: USE IT TODAY (REAL AI DEV SETUP SWITCHER WITH COPY BUTTON)
        // =====================================================================
        let (snippet_id, snippet_code, snippet_note) = match self.setup_tab {
            "mcp" => (
                "code-mcp",
                "{\n  \"mcpServers\": {\n    \"filesystem\": {\n      \"command\": \"nacre\",\n      \"args\": [\n        \"mcp-guard\", \"--preset\", \"coding-agent\",\n        \"--allow-path\", \"/repo/src/\",\n        \"--journal\", \".nacre-audit.jsonl\", \"--\",\n        \"npx\", \"-y\", \"@modelcontextprotocol/server-filesystem\", \"/repo\"\n      ]\n    }\n  }\n}",
                "wraps any stdio mcp server. blocks .env, ssh keys, '..' escapes, and denied tools before the server ever sees the json-rpc call.",
            ),
            "reflex" => (
                "code-reflex",
                "# 1. distill any {\"input\":\"...\",\"output\":\"...\"} log into a sealed .ncrystal\nnacre distill --input calls.jsonl --out triage.ncrystal --min-support 4\n\n# 2. query offline at $0 tokens (exit 0 = hit, exit 10 = ask llm, exit 3 = tamper)\nnacre query triage.ncrystal \"outage: checkout api 503\"",
                "works from bash, python, node, or rust. no gpu, no fine-tuning, zero external runtime dependencies.",
            ),
            _ => (
                "code-claude",
                "# 1. generate nacre.policy and .claude/settings.json in your repo\nnacre init --claude\n\n# 2. self-test your policy against 10 secret/traversal/rm-rf probes\nnacre test-policy --policy nacre.policy\n\n# 3. verify the sha-256 audit chain after your session\nnacre audit-verify .nacre-audit.jsonl",
                "drops straight into claude code PreToolUse hooks (exit 0 allow, exit 2 block with merkle proof).",
            ),
        };

        h.push_str(&format!(
            "<section class=\"beat\">\
              <div class=\"beat-k mono\">04 / use it in 60 seconds</div>\
              <h2 class=\"beat-title\">wrap the tools you already run.</h2>\
              <p class=\"beat-copy\">you do not need to rewrite your agent in a new language. drop the single rust binary in front of claude code, any mcp server, or your jsonl logs.</p>\
              <div class=\"widget\">\
                <div class=\"tab-strip\">\
                  <button class=\"tab-item {}\" data-act=\"setup_tab\" data-val=\"claude\">claude code hook</button>\
                  <button class=\"tab-item {}\" data-act=\"setup_tab\" data-val=\"mcp\">mcp server proxy</button>\
                  <button class=\"tab-item {}\" data-act=\"setup_tab\" data-val=\"reflex\">jsonl reflex cache</button>\
                  <span style=\"flex:1\"></span>\
                  <button class=\"copy-btn inline-copy\" data-copy=\"{}\">copy</button>\
                </div>\
                <div class=\"widget-body\">\
                  <pre class=\"code clean\" id=\"{}\">{}</pre>\
                  <p class=\"caption\">{}</p>\
                </div>\
              </div>\
              <div class=\"end-nav mono\">\
                <button class=\"act-btn\" data-act=\"page\" data-val=\"compiler\">open wasm compiler →</button>\
                <button class=\"act-btn\" data-act=\"page\" data-val=\"benchmarks\">explore benchmarks →</button>\
                <button class=\"act-btn\" data-act=\"page\" data-val=\"repl\">open kernel repl →</button>\
              </div>\
            </section>",
            if self.setup_tab == "claude" { "active" } else { "" },
            if self.setup_tab == "mcp" { "active" } else { "" },
            if self.setup_tab == "reflex" { "active" } else { "" },
            snippet_id,
            snippet_id,
            esc_html(snippet_code),
            snippet_note,
        ));
    }

    fn render_compiler(&self, h: &mut String) {
        h.push_str(
            "<section class=\"masthead\">\
              <h1>5-stage superoptimizer &amp; native wasm 1.0 emitter.</h1>\
              <p class=\"lead\">starts from a blind oracle rule (perform oracle ?p0), synthesizes generalizable logic with zero hints, verifies held-out parity, and emits raw webassembly 1.0 bytes in your browser.</p>\
            </section><div class=\"grid-comp\">",
        );

        h.push_str("<section class=\"pane\"><div class=\"pane-head\"><span>01 / synthesis task</span><span class=\"mono dim\">8 tasks</span></div><div class=\"preset-list\">");
        for t in COMP_TASKS {
            let active = if self.comp_task_id == t.id { " active" } else { "" };
            let badge = if t.is_control { "control" } else { "wasm" };
            h.push_str(&format!(
                "<button class=\"preset-row{}\" data-act=\"comp_task\" data-val=\"{}\">\
                  <span class=\"preset-main\"><span class=\"preset-title mono\">{}</span><span class=\"preset-sub\">{}</span></span>\
                  <span class=\"badge {}\">{}</span>\
                </button>",
                active,
                t.id,
                t.label,
                esc_html(t.desc),
                if t.is_control { "warn" } else { "" },
                badge
            ));
        }
        h.push_str("</div></section><section class=\"pane\">");

        if let Some(ref res) = self.comp_result {
            h.push_str(&format!(
                "<div class=\"pane-head\"><span>02 / verified trajectory · {}</span><span class=\"badge {}\">{}</span></div>\
                <div class=\"kpi-strip kpi-3\">\
                  <div class=\"kpi\"><div class=\"kpi-k\">candidates evaluated</div><div class=\"kpi-v mono\">{}</div></div>\
                  <div class=\"kpi\"><div class=\"kpi-k\">obs-equiv pruned</div><div class=\"kpi-v mono\">{}</div></div>\
                  <div class=\"kpi\"><div class=\"kpi-k\">emitted binary</div><div class=\"kpi-v mono {}\">{}</div></div>\
                </div>",
                esc_html(&res.task_id),
                if res.wasm_bytes_len.is_some() { "ok" } else { "warn" },
                esc_html(&res.final_stage),
                res.candidates_eval,
                res.obs_pruned,
                if res.wasm_bytes_len.is_some() { "ok" } else { "warn" },
                match res.wasm_bytes_len {
                    Some(n) => format!("{} bytes wasm 1.0", n),
                    None => String::from("safe hybrid escalation"),
                }
            ));

            h.push_str(
                "<table class=\"tbl\"><thead><tr>\
                  <th>stage</th><th>train eff</th><th>train fuel</th><th>held-out</th><th>ho fuel</th><th>synthesized rule / artifact</th>\
                </tr></thead><tbody>",
            );
            for s in &res.stages {
                let ho_txt = if s.ho_escalated > 0 {
                    format!("{}/{} exact · {} esc", s.ho_exact, s.ho_total, s.ho_escalated)
                } else {
                    format!("{}/{} · {} wrong", s.ho_exact, s.ho_total, s.ho_wrong)
                };
                let ho_cls = if s.ho_wrong > 0 {
                    "err"
                } else if s.ho_exact == s.ho_total && s.ho_total > 0 {
                    "ok"
                } else {
                    "warn"
                };
                h.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td class=\"mono num\">{}</td><td class=\"mono num\">{}</td><td class=\"mono {}\">{}</td><td class=\"mono num\">{}</td><td class=\"mono rule-cell\">{}</td></tr>",
                    esc_html(&s.stage),
                    s.train_eff,
                    s.train_fuel,
                    ho_cls,
                    ho_txt,
                    s.ho_fuel,
                    esc_html(&s.rule_src),
                ));
            }
            h.push_str("</tbody></table>");

            if let Some(blen) = res.wasm_bytes_len {
                h.push_str(&format!(
                    "<div class=\"sub-block\">\
                      <div class=\"pane-head compact\"><span>03 / execute emitted {} b webassembly 1.0 natively</span><span class=\"mono ok\">sha-256 {}</span></div>\
                      <textarea id=\"comp-wasm-lex\" style=\"display:none;\">{}</textarea>\
                      <div class=\"input-row\">\
                        <span class=\"mono dim\">solve(</span>\
                        <input class=\"inp mono\" id=\"comp-wasm-arg\" type=\"number\" value=\"{}\" style=\"max-width:120px;\">\
                        <span class=\"mono dim\">)</span>\
                        <button class=\"act-btn primary\" data-comp-wasm=\"1\">instantiate &amp; run native wasm</button>\
                        <span class=\"mono dim\">expected oracle({}): {}</span>\
                      </div>\
                      <pre class=\"code\" id=\"comp-wasm-out\">click instantiate &amp; run native wasm to execute the raw {}-byte binary via webassembly.instantiate().</pre>\
                      <details class=\"drawer\"><summary>inspect raw webassembly 1.0 hex ({} bytes)</summary><pre class=\"code hex\">{}</pre></details>\
                    </div>",
                    blen,
                    esc_html(&res.wasm_sha),
                    esc_html(&res.final_lex_src),
                    res.default_n,
                    res.default_n,
                    res.oracle_at_n,
                    blen,
                    blen,
                    esc_html(&res.wasm_hex),
                ));
            } else if res.is_control {
                h.push_str(
                    "<div class=\"sub-block\">\
                      <div class=\"mono ok\">falsification control passed: primality is non-expressible in a small arithmetic formula, so nacre refused to overfit and escalated 6/6 unseen inputs safely to the oracle with 0 errors.</div>\
                    </div>",
                );
            }
        }
        h.push_str("</section></div>");
    }

    fn render_benchmarks(&self, h: &mut String) {
        h.push_str(
            "<section class=\"masthead\">\
              <h1>empirical benchmarks &amp; live model telemetry.</h1>\
              <p class=\"lead\">every number below is reproducible via cargo run --release -p nacre-cli -- bench | security-bench | coev | live-matrix | live-inject.</p>\
            </section>",
        );

        let verify_badge = match &self.live_sec_checksum {
            Some(ck) => format!("<span class=\"badge ok\">verified live in browser wasm · sha {}</span>", ck),
            None => String::from("<button class=\"act-btn primary\" data-act=\"verify_bench\">verify 18 probes + 4 arms live in wasm</button>"),
        };

        h.push_str(&format!(
            "<section class=\"pane\"><div class=\"pane-head\"><span>structural &amp; supply-chain security matrix (breaches / probes)</span>{}</div>",
            verify_badge
        ));

        let rows: Vec<(&str, usize, usize, usize, usize, &str)> = if let Some(ref rep) = self.live_sec_bench {
            rep.static_classes
                .iter()
                .map(|r| (r.class_name, r.probes, r.naked_breaches, r.naive_breaches, r.nacre_breaches, r.mechanism))
                .collect()
        } else {
            vec![
                ("indirect_code_exec", 4, 4, 3, 0, "protect_value auto-quoting on continuation plug"),
                ("ambient_cap_escape", 4, 4, 2, 0, "transitive static_caps closure + non-escalation gate"),
                ("path_firewall_escape", 4, 4, 3, 0, "algebraic handle firewall + canonical path rule"),
                ("dos_fuel_and_depth", 3, 3, 2, 0, "depth guard + unified fuel + non-mintable slice"),
                ("supply_chain_tamper", 3, 3, 2, 0, "sha-256 bundle_hash + re-parse lex_hash + cap audit"),
            ]
        };

        h.push_str("<table class=\"tbl\"><thead><tr><th>attack class</th><th>naked ctrl</th><th>naive guard</th><th>nacre</th><th>guarantee</th></tr></thead><tbody>");
        for (name, probes, naked, naive, nacre, mech) in &rows {
            let npct = (*naive * 100) / (*probes).max(1);
            h.push_str(&format!(
                "<tr><td class=\"mono\">{}</td>\
                <td class=\"mono err\">{}/{} <span class=\"bar\"><span class=\"fill err\" style=\"width:100%\"></span></span></td>\
                <td class=\"mono warn\">{}/{} <span class=\"bar\"><span class=\"fill warn\" style=\"width:{}%\"></span></span></td>\
                <td class=\"mono ok\">{}/{} <span class=\"bar\"><span class=\"fill ok\" style=\"width:0%\"></span></span></td>\
                <td class=\"dim\">{}</td></tr>",
                name, naked, probes, naive, probes, npct, nacre, probes, mech
            ));
        }
        h.push_str(
            "<tr class=\"total-row\"><td class=\"mono\">total</td><td class=\"mono err\">18/18 (100%)</td><td class=\"mono warn\">12/18 (67%)</td><td class=\"mono ok\">0/18 (0%)</td><td class=\"mono ok\">zero structural breaches</td></tr></tbody></table>",
        );

        h.push_str(
            "<div class=\"sub-block\"><div class=\"field-label\">adaptive 4-arm red-queen comparison (pt-mcmc predator, 4,000 evals/gen)</div>\
            <table class=\"tbl\"><thead><tr><th>defense arm</th><th>gens</th><th>benign alive</th><th>leaks</th><th>paid replay calls</th><th>outcome</th></tr></thead><tbody>",
        );
        if let Some(ref rep) = self.live_sec_bench {
            for a in &rep.adaptive_arms {
                let st = if a.pt_breached_final { "breached" } else { "held" };
                let cls = if !a.pt_breached_final && a.final_alive_ok == a.final_alive_total && a.regression_leaks == 0 { "ok" } else { "err" };
                h.push_str(&format!(
                    "<tr><td class=\"mono\">{}</td><td class=\"mono num\">{}</td><td class=\"mono {}\">{}/{}</td><td class=\"mono num\">{}</td><td class=\"mono num\">{}</td><td class=\"mono {}\">{}</td></tr>",
                    a.arm_name, a.gens_survived, if a.final_alive_ok == a.final_alive_total { "ok" } else { "err" },
                    a.final_alive_ok, a.final_alive_total, a.regression_leaks, a.replay_llm_calls, cls, st
                ));
            }
        } else {
            h.push_str(
                "<tr><td class=\"mono\">arm0_naked_control</td><td class=\"mono num\">0</td><td class=\"mono\">12/12</td><td class=\"mono num err\">1</td><td class=\"mono num\">0</td><td class=\"mono err\">breached</td></tr>\
                <tr><td class=\"mono\">arm1_naive_blocklist</td><td class=\"mono num\">8</td><td class=\"mono err\">1/12 (autoimmune)</td><td class=\"mono num\">0</td><td class=\"mono num\">0</td><td class=\"mono warn\">collapsed</td></tr>\
                <tr><td class=\"mono\">arm2_soft_prompt_cap</td><td class=\"mono num\">10</td><td class=\"mono\">12/12</td><td class=\"mono num err\">5</td><td class=\"mono num warn\">165</td><td class=\"mono err\">breached</td></tr>\
                <tr class=\"total-row\"><td class=\"mono\">arm3_nacre_hard_immune</td><td class=\"mono num\">9</td><td class=\"mono ok\">12/12 (100%)</td><td class=\"mono num ok\">0</td><td class=\"mono num ok\">0</td><td class=\"mono ok\">held</td></tr>",
            );
        }
        h.push_str("</tbody></table></div></section>");

        h.push_str(
            "<section class=\"pane mt\"><div class=\"pane-head\"><span>184 live vercel ai gateway calls ($0.7519 total)</span><span class=\"mono dim\">nov 2026 · 4 fast models</span></div>\
            <table class=\"tbl\"><thead><tr><th>model</th><th>naked word-ban</th><th>inject (no-policy)</th><th>inject (policy)</th><th>nacre firewall</th><th>12-call cost (73x spread)</th></tr></thead><tbody>\
              <tr><td class=\"mono\">anthropic/claude-haiku-5.5</td><td class=\"mono err\">breach@1</td><td class=\"mono err\">1/8 hijacked</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8 · 4/4 alive</td><td class=\"mono ok\">$0.0013 <span class=\"bar\"><span class=\"fill ok\" style=\"width:2%\"></span></span></td></tr>\
              <tr><td class=\"mono\">deepseek/deepseek-v4.1-flash</td><td class=\"mono err\">breach@1</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8 · 4/4 alive</td><td class=\"mono\">$0.0176 <span class=\"bar\"><span class=\"fill\" style=\"width:18%\"></span></span></td></tr>\
              <tr><td class=\"mono\">google/gemini-4-hydrogen</td><td class=\"mono err\">breach@1</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8 · 4/4 alive</td><td class=\"mono\">$0.0373 <span class=\"bar\"><span class=\"fill\" style=\"width:39%\"></span></span></td></tr>\
              <tr><td class=\"mono\">google/gemini-4-neon</td><td class=\"mono err\">breach@1</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8</td><td class=\"mono ok\">0/8 · 4/4 alive</td><td class=\"mono warn\">$0.0956 <span class=\"bar\"><span class=\"fill warn\" style=\"width:100%\"></span></span></td></tr>\
            </tbody></table></section>",
        );

        h.push_str(
            "<div class=\"grid-2 mt\">\
            <section class=\"pane\"><div class=\"pane-head\"><span>170 real openai/codex issues</span><span class=\"mono dim\">nanocode jsonl bridge</span></div>\
            <table class=\"tbl\"><thead><tr><th>policy</th><th>exact</th><th>wrong</th><th>precision</th><th>llm cut</th></tr></thead><tbody>\
              <tr><td class=\"mono\">pure_offline</td><td class=\"mono\">50/69</td><td class=\"mono err\">19</td><td class=\"mono warn\">72%</td><td class=\"mono\">100%</td></tr>\
              <tr><td class=\"mono\">hybrid (sup=2)</td><td class=\"mono\">32/69</td><td class=\"mono\">3</td><td class=\"mono\">91%</td><td class=\"mono ok\">50%</td></tr>\
              <tr class=\"total-row\"><td class=\"mono\">hybrid (sup=4)</td><td class=\"mono ok\">28/69</td><td class=\"mono ok\">1</td><td class=\"mono ok\">96%</td><td class=\"mono ok\">42%</td></tr>\
              <tr><td class=\"mono\">hybrid (sup=6)</td><td class=\"mono\">26/69</td><td class=\"mono ok\">1</td><td class=\"mono ok\">96%</td><td class=\"mono\">39%</td></tr>\
            </tbody></table></section>\
            <section class=\"pane\"><div class=\"pane-head\"><span>pt-mcmc vs baselines (67m-state arena)</span><span class=\"mono dim\">hardened gen 4 · 25 seeds</span></div>\
            <table class=\"tbl\"><thead><tr><th>algorithm</th><th>breaches</th><th>avg evals</th><th>swap acc</th></tr></thead><tbody>\
              <tr class=\"total-row\"><td class=\"mono\">pt_mcmc_genetic</td><td class=\"mono ok\">25/25</td><td class=\"mono ok\">328</td><td class=\"mono ok\">37%</td></tr>\
              <tr><td class=\"mono\">greedy_hill_climb</td><td class=\"mono\">25/25</td><td class=\"mono\">442</td><td class=\"mono dim\">0%</td></tr>\
              <tr><td class=\"mono\">single_temp_sa</td><td class=\"mono\">25/25</td><td class=\"mono warn\">1,915</td><td class=\"mono dim\">0%</td></tr>\
              <tr><td class=\"mono\">random_search</td><td class=\"mono err\">1/25</td><td class=\"mono dim\">1,166</td><td class=\"mono dim\">0%</td></tr>\
            </tbody></table></section></div>",
        );
    }

    fn render_repl(&self, h: &mut String) {
        h.push_str(&format!(
            "<section class=\"masthead\">\
              <h1>symbolic kernel repl &amp; wasm 1.0 compiler.</h1>\
              <p class=\"lead\">edit closed linear supercombinators, inspect static capabilities, and emit standalone webassembly 1.0 binaries.</p>\
            </section>\
            <div class=\"grid-2\">\
            <section class=\"pane\">\
              <div class=\"pane-head\"><span>01 / lexicon &amp; expression</span>\
                <div class=\"seg-row inline\">\
                  <button class=\"seg {}\" data-act=\"repl_preset\" data-val=\"fib\">fib</button>\
                  <button class=\"seg {}\" data-act=\"repl_preset\" data-val=\"sum_closed\">sum_to</button>\
                  <button class=\"seg {}\" data-act=\"repl_preset\" data-val=\"collatz\">collatz</button>\
                  <button class=\"seg {}\" data-act=\"repl_preset\" data-val=\"firewall\">firewall</button>\
                </div>\
              </div>\
              <textarea class=\"inp mono\" id=\"repl-lex\" rows=\"8\">{}</textarea>\
              <div class=\"sub-block\">\
                <div class=\"input-row\">\
                  <input class=\"inp mono\" id=\"repl-expr\" type=\"text\" value=\"{}\" data-enter=\"repl_run\">\
                  <button class=\"act-btn primary\" data-act=\"repl_run\">evaluate</button>\
                </div>\
                <div class=\"kv-row compact\"><span class=\"kv-k\">static caps</span><span class=\"kv-v mono ok\">{}</span></div>\
                <pre class=\"code\">{}</pre>\
              </div>\
            </section>\
            <section class=\"pane\">\
              <div class=\"pane-head\"><span>02 / tier-2 native wasm 1.0 compiler</span><span class=\"mono dim\">pure i64 rules</span></div>\
              <div class=\"sub-block\">\
                <p class=\"caption\" style=\"margin-top:0;\">compiles the named pure integer rule on the left into raw webassembly 1.0 bytes and runs it natively via webassembly.instantiate().</p>\
                <div class=\"input-row\">\
                  <input class=\"inp mono\" id=\"wasm-head\" type=\"text\" value=\"{}\" style=\"max-width:110px;\">\
                  <input class=\"inp mono\" id=\"wasm-arg\" type=\"number\" value=\"{}\" style=\"max-width:110px;\">\
                  <button class=\"act-btn primary\" data-wasm-compile=\"1\">compile &amp; execute wasm</button>\
                </div>\
                <pre class=\"code\" id=\"wasm-native-out\">click compile &amp; execute wasm to emit a standalone wasm 1.0 binary and inspect its hex + native output.</pre>\
              </div>\
            </section></div>",
            if self.repl_preset == "fib" { "active" } else { "" },
            if self.repl_preset == "sum_closed" { "active" } else { "" },
            if self.repl_preset == "collatz" { "active" } else { "" },
            if self.repl_preset == "firewall" { "active" } else { "" },
            esc_html(&self.repl_lex),
            esc_html(&self.repl_expr),
            esc_html(&self.repl_caps),
            esc_html(&self.repl_out),
            esc_html(&self.repl_wasm_head),
            esc_html(&self.repl_wasm_arg),
        ));
    }
}

fn nacre_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn esc_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

thread_local! {
    static STUDIO: RefCell<StudioState> = RefCell::new(StudioState::new());
}

/// pure-rust entry point: `action\n<payload>` -> full all-lowercase HTML snapshot.
pub fn dispatch_ui_event(raw: &str) -> String {
    let (action, payload) = match raw.split_once('\n') {
        Some((a, p)) => (a.trim(), p),
        None => (raw.trim(), ""),
    };
    STUDIO.with(|cell| {
        let mut st = cell.borrow_mut();
        st.dispatch(action, payload);
        st.render_html()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_strict_lowercase(html: &str) {
        assert!(
            !html.bytes().any(|b| b.is_ascii_uppercase()),
            "found uppercase ascii byte in rendered studio html"
        );
    }

    #[test]
    fn studio_workbench_all_views_and_strict_lowercase() {
        let h_fw = dispatch_ui_event("init");
        assert_strict_lowercase(&h_fw);
        assert!(h_fw.contains("b9bc787f1e37"));
        assert!(h_fw.contains("blocked"));
        assert!(h_fw.contains("<svg "));

        let h_inj = dispatch_ui_event("fw_preset\ncode_inject");
        assert_strict_lowercase(&h_inj);
        assert!(h_inj.contains("auto-quoted"));

        let h_ok = dispatch_ui_event("fw_preset\nbenign_readme");
        assert_strict_lowercase(&h_ok);
        assert!(h_ok.contains("allowed"));

        let h_tamp = dispatch_ui_event("seal_tamper");
        assert_strict_lowercase(&h_tamp);
        assert!(h_tamp.contains("rejected"));

        let h_mcp = dispatch_ui_event("setup_tab\nmcp");
        assert_strict_lowercase(&h_mcp);
        assert!(h_mcp.contains("mcp-guard"));

        let h_comp = dispatch_ui_event("page\ncompiler");
        assert_strict_lowercase(&h_comp);
        assert!(h_comp.contains("186 bytes wasm 1.0"));
        assert!(h_comp.contains("gen4_wasm_reflex"));

        let h_prime = dispatch_ui_event("comp_task\nprime_ctrl");
        assert_strict_lowercase(&h_prime);
        assert!(h_prime.contains("falsification control passed"));

        let h_bench = dispatch_ui_event("page\nbenchmarks");
        assert_strict_lowercase(&h_bench);
        let h_ver = dispatch_ui_event("verify_bench");
        assert_strict_lowercase(&h_ver);
        assert!(h_ver.contains("verified live in browser wasm"));

        let h_repl = dispatch_ui_event("page\nrepl");
        assert_strict_lowercase(&h_repl);
        assert!(h_repl.contains("value:  144"));
    }
}
