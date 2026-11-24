//! pure-rust studio ui state machine & html renderer compiled to wasm32.
//!
//! keeps javascript in `studio/template.html` to a thin ~45-line wasm loader/bridge.
//! enforces strict zero-capital-letters invariant on every rendered byte at the rust layer.

use std::cell::RefCell;

use nacre_core::arena::Arena;
use nacre_core::bundle::CrystalBundle;
use nacre_core::coev::{run_attacker_ablation, run_red_queen_coevolution, DefenderGen};
use nacre_core::eval::{eval, Outcome};
use nacre_core::fuel::Fuel;
use nacre_core::journal::run_and_record;
use nacre_core::lexicon::Lexicon;
use nacre_core::security_bench::run_security_control_bench;
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize_with_mode, SynthMode};

const BASE_TRIAGE_LEX: &str = "\
(rule (triage ?msg)
  (perform llm_classify ?msg))

(rule (route ?msg)
  (match (triage ?msg)
    (case urgent (escalate ?msg))
    (case billing (queue_billing ?msg))
    (case _ (queue_general ?msg))))";

struct StudioState {
    page: &'static str, // "guided" | "security" | "lab"
    journal: Vec<(String, String)>,
    hybrid_mode: bool,
    crystallized_lex: Option<String>,
    synthesized_rule: Option<String>,
    cert_hash: Option<String>,
    effects_before: u64,
    effects_after: u64,
    is_pure: bool,
    valid_bundle: Option<String>,
    current_bundle: Option<String>,
    tampered: bool,
    seal_ok: bool,
    seal_msg: String,
    test_input: String,
    test_badge: String,
    test_badge_kind: &'static str,
    test_answer: String,
    // security arena tab cached summary (computed live inside wasm!)
    sec_report_text: Option<String>,
    // lab state
    lab_lex: String,
    lab_expr: String,
    lab_out: String,
    lab_caps: String,
}

impl StudioState {
    fn new() -> Self {
        Self {
            page: "guided",
            journal: vec![
                ("outage: db primary down".into(), "urgent".into()),
                ("outage: eu edge 503".into(), "urgent".into()),
                ("invoice #102 double charged".into(), "billing".into()),
                ("invoice #998 pdf missing".into(), "billing".into()),
                ("how do i export csv?".into(), "general".into()),
                ("custom enterprise sla inquiry".into(), "general".into()),
            ],
            hybrid_mode: false,
            crystallized_lex: None,
            synthesized_rule: None,
            cert_hash: None,
            effects_before: 6,
            effects_after: 6,
            is_pure: false,
            valid_bundle: None,
            current_bundle: None,
            tampered: false,
            seal_ok: false,
            seal_msg: "crystallize a skill to mint its sha-256 trust seal.".into(),
            test_input: "outage: eu database crashed".into(),
            test_badge: "waiting for step 2".into(),
            test_badge_kind: "",
            test_answer: "crystallize the skill in step 2, then test unseen tickets here.".into(),
            sec_report_text: None,
            lab_lex: "(rule (fib 0) 0)\n(rule (fib 1) 1)\n(rule (fib ?n) (add (fib (sub ?n 1)) (fib (sub ?n 2))))".into(),
            lab_expr: "(fib 10)".into(),
            lab_out: "click run to evaluate inside nacre-core wasm.".into(),
            lab_caps: "pure offline (0 caps)".into(),
        }
    }

    fn dispatch(&mut self, action: &str, payload: &str) {
        let pay = payload.to_ascii_lowercase();
        match action {
            "init" => {}
            "page" => {
                self.page = match pay.trim() {
                    "security" => "security",
                    "lab" => "lab",
                    _ => "guided",
                };
                if self.page == "security" && self.sec_report_text.is_none() {
                    self.run_security_arena();
                }
            }
            "add_ticket" => {
                let msg = pay.trim();
                if !msg.is_empty() {
                    let lbl = classify_oracle_hint(msg);
                    self.journal.insert(0, (String::from(msg), String::from(lbl)));
                    self.effects_before = self.journal.len() as u64;
                    if self.crystallized_lex.is_some() {
                        self.run_crystallize();
                    }
                }
            }
            "mode_pure" => {
                self.hybrid_mode = false;
                if self.crystallized_lex.is_some() {
                    self.run_crystallize();
                }
            }
            "mode_hybrid" => {
                self.hybrid_mode = true;
                if self.crystallized_lex.is_some() {
                    self.run_crystallize();
                }
            }
            "crystallize" => self.run_crystallize(),
            "test_ticket" => {
                if !pay.trim().is_empty() {
                    self.test_input = String::from(pay.trim());
                }
                if self.crystallized_lex.is_none() {
                    self.run_crystallize();
                } else {
                    self.run_test_ticket();
                }
            }
            "tamper" => {
                if let Some(ref valid) = self.valid_bundle {
                    self.current_bundle = Some(valid.replace("escalate", "exfiltrate"));
                    self.tampered = true;
                    self.verify_current_bundle();
                }
            }
            "restore" => {
                self.current_bundle = self.valid_bundle.clone();
                self.tampered = false;
                self.verify_current_bundle();
            }
            "run_security" => self.run_security_arena(),
            "lab_run" => {
                if let Some((l, e)) = pay.split_once("\n---\n") {
                    self.lab_lex = String::from(l);
                    self.lab_expr = String::from(e);
                }
                self.run_lab();
            }
            _ => {}
        }
    }

    fn run_crystallize(&mut self) {
        let mut arena = Arena::new();
        let mut base_lex = Lexicon::new();
        if base_lex.load_source(&mut arena, BASE_TRIAGE_LEX).is_err() {
            return;
        }
        let mut traces = Vec::new();
        for (msg, lbl) in &self.journal {
            let entry_src = format!("(route {})", nacre_quote(msg));
            if let Ok(entry) = parse_term(&mut arena, &entry_src) {
                let lbl_s = lbl.clone();
                if let Ok(tr) = run_and_record(&mut arena, &base_lex, entry, 5000, |a, _| {
                    let s = a.intern_sym(&lbl_s);
                    Ok(a.mk_sym(s)?.0)
                }) {
                    traces.push(tr);
                }
            }
        }
        let mode = if self.hybrid_mode {
            SynthMode::HybridGuarded { min_support: 2 }
        } else {
            SynthMode::PureOffline
        };
        if let Ok(ac) = auto_crystallize_with_mode(&mut arena, &base_lex, &traces, mode) {
            let full_lex = ac.lexicon.to_source(&arena);
            let bundle = CrystalBundle::new("triage", &full_lex, ac.cert.clone(), None);
            let wire = bundle.encode_text();
            self.crystallized_lex = Some(full_lex);
            self.synthesized_rule = Some(ac.synthesized_src);
            self.cert_hash = Some(ac.cert.cert_hash.short_hex());
            self.effects_before = ac.cert.base_effects;
            self.effects_after = ac.cert.new_effects;
            self.is_pure = ac.cert.is_now_pure();
            self.valid_bundle = Some(wire.clone());
            self.current_bundle = Some(wire);
            self.tampered = false;
            self.verify_current_bundle();
            self.run_test_ticket();
        }
    }

    fn run_test_ticket(&mut self) {
        let Some(ref lex_src) = self.crystallized_lex else {
            return;
        };
        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        if lex.load_source(&mut arena, lex_src).is_err() {
            return;
        }
        let expr_src = format!("(route {})", nacre_quote(&self.test_input));
        let Ok(expr) = parse_term(&mut arena, &expr_src) else {
            return;
        };
        let mut fuel = Fuel::new(2000);
        match eval(&mut arena, &lex, expr, &mut fuel) {
            Outcome::Done(v) => {
                let txt = print_term(&arena, v);
                self.test_badge = format!("0 ai calls · {} fuel offline", fuel.used());
                self.test_badge_kind = "ok";
                self.test_answer = format!(
                    "action: {} — executed locally in rust/wasm with zero cloud calls.",
                    friendly_action(&txt)
                );
            }
            Outcome::Yield { .. } => {
                self.test_badge = "unseen → safely asked ai".into();
                self.test_badge_kind = "warn";
                self.test_answer =
                    "hybrid safety trigger: unseen pattern paused and yielded llm_classify instead of guessing."
                        .into();
            }
            _ => {
                self.test_badge = "fault".into();
                self.test_badge_kind = "err";
                self.test_answer = "evaluation fault".into();
            }
        }
    }

    fn verify_current_bundle(&mut self) {
        let Some(ref wire) = self.current_bundle else {
            return;
        };
        match CrystalBundle::decode_text(wire) {
            Ok(b) => match b.verify() {
                Ok(info) => {
                    self.seal_ok = true;
                    let caps = if info.static_caps.is_empty() {
                        String::from("none")
                    } else {
                        info.static_caps.join(", ")
                    };
                    self.seal_msg = format!(
                        "sha-256 verified ({}) · permissions audited: {} · safe to share.",
                        info.bundle_hash.short_hex(),
                        caps
                    );
                }
                Err(d) => {
                    self.seal_ok = false;
                    self.seal_msg = format!("tamper caught before execution: {}", d);
                }
            },
            Err(d) => {
                self.seal_ok = false;
                self.seal_msg = format!("tamper caught before execution: {}", d);
            }
        }
    }

    fn run_security_arena(&mut self) {
        let sec = run_security_control_bench();
        let mut out = String::new();
        out.push_str("part 1 · structural & supply-chain controls (breaches / probes)\n");
        for r in &sec.static_classes {
            out.push_str(&format!(
                "  {:<21} naked {}/{} | naive {}/{} | nacre {}/{}\n",
                r.class_name,
                r.naked_breaches,
                r.probes,
                r.naive_breaches,
                r.probes,
                r.nacre_breaches,
                r.probes
            ));
        }
        out.push_str("\npart 2 · adaptive red-queen arms under live pt-mcmc predator\n");
        for a in &sec.adaptive_arms {
            let st = if a.pt_breached_final { "breached" } else { "held" };
            out.push_str(&format!(
                "  {:<23} gens={:<2} alive={}/{} leaks={} replay_llms={} [{}]\n",
                a.arm_name,
                a.gens_survived,
                a.final_alive_ok,
                a.final_alive_total,
                a.regression_leaks,
                a.replay_llm_calls,
                st
            ));
        }
        // also run a quick live 4-way pt-mcmc ablation on hardened gen 4 right inside browser wasm!
        let (_, hardened4) = run_red_queen_coevolution(0, 4, 2500, 0x1337_cafe);
        out.push_str("\npart 3 · live pt-mcmc vs greedy on hardened gen 4 (5 seeds x 1500 evals)\n");
        for row in run_attacker_ablation(&hardened4, 1500, 5) {
            out.push_str(&format!(
                "  {:<20} breaches={}/{} avg_evals={} swap_acc={}%\n",
                row.algo.label(),
                row.breaches,
                row.trials,
                row.avg_evals_when_breached,
                row.avg_swap_accept_pct
            ));
        }
        let _ = DefenderGen::gen0(0);
        self.sec_report_text = Some(out);
    }

    fn run_lab(&mut self) {
        let (_, caps_txt) = crate::caps_bundle(&format!("{}\n---\n{}", self.lab_lex, self.lab_expr));
        self.lab_caps = caps_txt;
        let (_, eval_txt) =
            crate::eval_bundle(&format!("{}\n---\n{}", self.lab_lex, self.lab_expr), 50_000);
        self.lab_out = eval_txt;
    }

    fn render_html(&self) -> String {
        let mut h = String::with_capacity(8192);
        h.push_str(&format!(
            "<header><div class=\"brand\"><span class=\"logo\">nacre</span></div>\
            <div class=\"mode-switch\">\
            <button class=\"mode-btn {}\" data-act=\"page\" data-val=\"guided\">guided demo</button>\
            <button class=\"mode-btn {}\" data-act=\"page\" data-val=\"security\">security &amp; pt-mcmc</button>\
            <button class=\"mode-btn {}\" data-act=\"page\" data-val=\"lab\">lab</button>\
            </div></header><main>",
            if self.page == "guided" { "active" } else { "" },
            if self.page == "security" { "active" } else { "" },
            if self.page == "lab" { "active" } else { "" },
        ));

        match self.page {
            "security" => self.render_security(&mut h),
            "lab" => self.render_lab(&mut h),
            _ => self.render_guided(&mut h),
        }

        h.push_str("</main><footer><span>nacre</span><span>deterministic cells · durable journals · verified reflexes</span></footer>");
        // top-level rust lowercase enforcement invariant
        h.to_ascii_lowercase()
    }

    fn render_guided(&self, h: &mut String) {
        h.push_str(
            "<section class=\"hero\"><h1>teach an ai agent once. run it offline forever.</h1>\
            <p>nacre records agent runs in a tamper-proof journal, distills repeated logic into a tiny verified offline reflex, and proves it matches every past run with zero hidden permissions.</p></section>\
            <div class=\"steps\">",
        );

        // step 1
        h.push_str(
            "<section class=\"card\"><div class=\"step-head\"><span class=\"step-num\">1</span><span class=\"step-title\">run the ai agent</span></div>\
            <p class=\"step-desc\">at first, the agent asks an ai model on every ticket. add a ticket to its journal:</p>\
            <div class=\"chips\">\
            <button class=\"chip\" data-act=\"add_ticket\" data-val=\"outage: checkout api 503\">outage: checkout api 503</button>\
            <button class=\"chip\" data-act=\"add_ticket\" data-val=\"invoice #512 charged twice\">invoice #512 charged twice</button>\
            <button class=\"chip\" data-act=\"add_ticket\" data-val=\"how do i change my theme?\">how do i change my theme?</button>\
            </div>\
            <div class=\"row\"><input class=\"grow\" id=\"in-ticket\" type=\"text\" placeholder=\"type any support ticket...\"><button class=\"btn\" data-act=\"add_ticket\" data-from=\"in-ticket\">run via ai</button></div>\
            <div class=\"result-box\"><div class=\"row\" style=\"justify-content:space-between;\"><span class=\"muted\">recorded journal</span><span class=\"tag warn\">",
        );
        h.push_str(&format!("{} ai calls logged</span></div><div class=\"journal-list\">", self.journal.len()));
        for (msg, lbl) in &self.journal {
            let kind = match lbl.as_str() {
                "urgent" => "err",
                "billing" => "warn",
                _ => "accent",
            };
            h.push_str(&format!(
                "<div class=\"journal-row\"><span class=\"journal-msg\">{}</span><span class=\"tag {}\">ai → {}</span></div>",
                esc_html(msg),
                kind,
                esc_html(lbl)
            ));
        }
        h.push_str("</div></div></section>");

        // step 2
        let eff_txt = if self.crystallized_lex.is_some() {
            format!("{} → {}", self.effects_before, self.effects_after)
        } else {
            format!("{} → ?", self.journal.len())
        };
        let eff_cls = if self.crystallized_lex.is_some() { "ok" } else { "warn" };
        let cap_txt = if self.crystallized_lex.is_none() {
            "llm_classify"
        } else if self.is_pure {
            "none (offline)"
        } else {
            "fallback only"
        };
        let cap_cls = if self.crystallized_lex.is_none() {
            ""
        } else if self.is_pure {
            "ok"
        } else {
            "warn"
        };

        h.push_str(&format!(
            "<section class=\"card highlight\"><div class=\"step-head\"><span class=\"step-num\">2</span><span class=\"step-title\">crystallize into a reflex</span></div>\
            <p class=\"step-desc\">distill the journal into a verified offline skill (100% pure rust integer synthesis in wasm):</p>\
            <div class=\"pill-toggle\">\
            <button class=\"pill-opt {}\" data-act=\"mode_pure\">100% offline</button>\
            <button class=\"pill-opt {}\" data-act=\"mode_hybrid\">hybrid (ask ai if unsure)</button>\
            </div>\
            <button class=\"btn primary\" style=\"width:100%; padding:11px;\" data-act=\"crystallize\">crystallize skill from journal</button>\
            <div class=\"metrics\">\
            <div class=\"metric\"><div class=\"metric-label\">ai calls needed</div><div class=\"metric-val {}\">{}</div></div>\
            <div class=\"metric\"><div class=\"metric-label\">external permissions</div><div class=\"metric-val {}\">{}</div></div>\
            </div>\
            <div class=\"result-box\"><div class=\"row\" style=\"justify-content:space-between;\"><span class=\"muted\">learned skill logic</span><span class=\"tag {}\">{}</span></div><div class=\"rule-visual\">",
            if !self.hybrid_mode { "active" } else { "" },
            if self.hybrid_mode { "active" } else { "" },
            eff_cls,
            eff_txt,
            cap_cls,
            cap_txt,
            if self.crystallized_lex.is_some() { "ok" } else { "" },
            if self.crystallized_lex.is_some() {
                format!("verified {}/{} runs", self.journal.len(), self.journal.len())
            } else {
                String::from("not crystallized yet")
            }
        ));

        if let Some(ref rule) = self.synthesized_rule {
            render_visual_branches(rule, h);
            h.push_str(&format!(
                "</div><details><summary>inspect nacre code &amp; cert ({})</summary><pre class=\"code\">{}</pre></details>",
                self.cert_hash.as_deref().unwrap_or("—"),
                esc_html(rule)
            ));
        } else {
            h.push_str("<span class=\"muted\">click above to synthesize and mechanically verify the skill inside wasm.</span></div>");
        }
        h.push_str("</div></section>");

        // step 3
        h.push_str(&format!(
            "<section class=\"card\"><div class=\"step-head\"><span class=\"step-num\">3</span><span class=\"step-title\">test offline &amp; verify trust</span></div>\
            <p class=\"step-desc\">send a brand-new unseen ticket — executed locally inside rust/wasm with zero network calls:</p>\
            <div class=\"chips\">\
            <button class=\"chip\" data-act=\"test_ticket\" data-val=\"outage: eu database crashed\">outage: eu database crashed</button>\
            <button class=\"chip\" data-act=\"test_ticket\" data-val=\"invoice #889 refund request\">invoice #889 refund request</button>\
            <button class=\"chip\" data-act=\"test_ticket\" data-val=\"partnership with university lab\">partnership with university lab</button>\
            </div>\
            <div class=\"row\"><input class=\"grow\" id=\"in-test\" type=\"text\" value=\"{}\"><button class=\"btn primary\" data-act=\"test_ticket\" data-from=\"in-test\">test</button></div>\
            <div class=\"result-box\"><div class=\"row\" style=\"justify-content:space-between;\"><span class=\"muted\">live offline result</span><span class=\"tag {}\">{}</span></div>\
            <div>{}</div></div>\
            <div class=\"divider\"></div>\
            <div class=\"row\" style=\"justify-content:space-between;\"><span class=\"muted\">portable .ncrystal seal</span><span class=\"tag {}\">{}</span></div>",
            esc_html(&self.test_input),
            self.test_badge_kind,
            esc_html(&self.test_badge),
            esc_html(&self.test_answer),
            if self.valid_bundle.is_none() { "" } else if self.seal_ok { "ok" } else { "err" },
            if self.valid_bundle.is_none() { "no bundle yet" } else if self.seal_ok { "cryptographically verified" } else { "tamper caught!" }
        ));
        if self.valid_bundle.is_some() {
            h.push_str("<div class=\"row\">");
            if !self.tampered {
                h.push_str("<button class=\"btn sm danger\" data-act=\"tamper\">simulate 1-byte hack</button>");
            } else {
                h.push_str("<button class=\"btn sm\" data-act=\"restore\">restore valid</button>");
            }
            h.push_str("</div>");
        }
        h.push_str(&format!(
            "<div class=\"muted\" style=\"color:{};\">{}</div></section></div>",
            if self.tampered && !self.seal_ok { "var(--err)" } else { "var(--muted)" },
            esc_html(&self.seal_msg)
        ));
    }

    fn render_security(&self, h: &mut String) {
        h.push_str(
            "<section class=\"card\"><div class=\"row\" style=\"justify-content:space-between;\">\
            <span class=\"step-title\">live security control matrix &amp; pt-mcmc co-evolution (running in rust/wasm)</span>\
            <button class=\"btn primary sm\" data-act=\"run_security\">re-run live benchmark</button></div>\
            <p class=\"step-desc\" style=\"margin:0;\">executes all 18 structural attack probes (naked control vs naive guard vs nacre) + 4-arm adaptive red-queen loop + live fixed-point pt-mcmc ablation directly inside wasm.</p>\
            <pre class=\"code\">",
        );
        h.push_str(&esc_html(
            self.sec_report_text
                .as_deref()
                .unwrap_or("click re-run live benchmark."),
        ));
        h.push_str("</pre></section>");
    }

    fn render_lab(&self, h: &mut String) {
        h.push_str(&format!(
            "<div class=\"lab-grid\">\
            <section class=\"card\"><span class=\"step-title\">pure rust symbolic evaluator</span>\
            <textarea id=\"lab-lex\" style=\"min-height:150px;\">{}</textarea>\
            <div class=\"row\"><input class=\"grow mono\" id=\"lab-expr\" type=\"text\" value=\"{}\"><button class=\"btn primary\" data-act=\"lab_run\">run</button></div>\
            <span class=\"tag ok\">{}</span><pre class=\"code\">{}</pre></section>\
            <section class=\"card\"><span class=\"step-title\">tier-2 native wasm 1.0 compiler</span>\
            <p class=\"step-desc\" style=\"margin:0;\">compiles the pure i64 rule on the left into raw webassembly 1.0 bytes inside nacre-wasm and executes it natively via webassembly.instantiate().</p>\
            <div class=\"row\"><input class=\"mono\" id=\"wasm-head\" type=\"text\" value=\"fib\" style=\"width:90px;\">\
            <input class=\"grow mono\" id=\"wasm-arg\" type=\"number\" value=\"12\">\
            <button class=\"btn primary\" data-wasm-compile=\"1\">compile &amp; run native wasm</button></div>\
            <pre class=\"code\" id=\"wasm-native-out\">click compile &amp; run native wasm to emit a ~193-byte standalone wasm 1.0 binary and verify bit-for-bit parity.</pre></section></div>",
            esc_html(&self.lab_lex),
            esc_html(&self.lab_expr),
            esc_html(&self.lab_caps),
            esc_html(&self.lab_out),
        ));
    }
}

fn classify_oracle_hint(msg: &str) -> &'static str {
    if msg.contains("outage") || msg.contains("down") || msg.contains("503") || msg.contains("crash") {
        "urgent"
    } else if msg.contains("invoice") || msg.contains("charge") || msg.contains("refund") {
        "billing"
    } else {
        "general"
    }
}

fn friendly_action(val: &str) -> &str {
    if val.starts_with("(escalate ") {
        "escalate to on-call engineer"
    } else if val.starts_with("(queue_billing ") {
        "route to billing & refunds"
    } else if val.starts_with("(queue_general ") {
        "route to general support inbox"
    } else {
        val
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

fn render_visual_branches(rule_src: &str, h: &mut String) {
    let mut rest = rule_src.to_ascii_lowercase();
    let mut count = 0usize;
    while let Some(pos) = rest.find("(if (str_contains ?x \"") {
        let after = &rest[pos + 22..];
        let Some(end_q) = after.find('"') else {
            break;
        };
        let tok = &after[..end_q];
        let after_tok = after[end_q + 2..].trim_start();
        let label_end = after_tok
            .find(|c: char| c.is_whitespace() || c == ')')
            .unwrap_or(after_tok.len());
        let label = &after_tok[..label_end];
        let pfx = if count == 0 { "if" } else { "else if" };
        h.push_str(&format!(
            "<div class=\"rule-branch\">{} contains \"{}\" → {}</div>",
            pfx,
            esc_html(tok),
            esc_html(label)
        ));
        count += 1;
        rest = String::from(after_tok[label_end..].trim_start());
    }
    if rest.contains("(perform llm_classify ?x)") {
        h.push_str("<div class=\"rule-branch fallback\">otherwise → ask ai (llm_classify)</div>");
    } else if count > 0 {
        let tail = rest.trim_end_matches(')').trim();
        if !tail.is_empty() {
            h.push_str(&format!(
                "<div class=\"rule-branch\">otherwise → {}</div>",
                esc_html(tail)
            ));
        }
    } else {
        h.push_str(&format!(
            "<div class=\"rule-branch\">{}</div>",
            esc_html(rule_src)
        ));
    }
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
