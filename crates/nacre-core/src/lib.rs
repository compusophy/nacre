//! nacre-core: deterministic, zero-dep, `#![no_std]` symbolic cell kernel.
//!
//! four primitives, zero unsafe code, zero floats, zero clocks, zero external deps:
//!   1. `arena`: hash-consed merkle-dag terms (`TermId` + sha-256 `Hash256`)
//!   2. `lexicon`: closed linear supercombinator rules + static capability inference
//!   3. `eval`: fuel-bounded reducer with algebraic `perform`/`handle` and pure residual continuations
//!   4. `journal` & `distill`: durable merkle traces, offline replay, time-travel fork, and
//!      mechanically verified reflex crystallization.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod arena;
pub mod bundle;
pub mod coev;
pub mod diag;
pub mod distill;
pub mod eval;
pub mod evolve;
pub mod fuel;
pub mod hash;
pub mod journal;
pub mod lexicon;
pub mod nanocode_bridge;
pub mod pt_mcmc;
pub mod security_bench;
pub mod syntax;
pub mod synthesize;
pub mod wasm_emit;

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::arena::{Arena, Node};
    use crate::diag::DiagCode;
    use crate::distill::crystallize_from_source;
    use crate::eval::{eval, Outcome};
    use crate::fuel::Fuel;
    use crate::journal::{fork_from_event, replay_trace, run_and_record, Trace, TraceOutcome};
    use crate::lexicon::Lexicon;
    use crate::syntax::{parse_term, print_term};

    #[test]
    fn alpha_canonical_rule_hashing() {
        let mut a = Arena::new();
        let mut l1 = Lexicon::new();
        l1.load_source(&mut a, "(rule (inc ?x) (add ?x 1))").unwrap();

        let mut l2 = Lexicon::new();
        l2.load_source(&mut a, "(rule (inc ?totally_different) (add ?totally_different 1))")
            .unwrap();

        assert_eq!(l1.hash(&a), l2.hash(&a));
    }

    #[test]
    fn linear_pattern_and_closure_gates() {
        let mut a = Arena::new();
        let mut lex = Lexicon::new();
        let dup = lex.load_source(&mut a, "(rule (bad ?x ?x) ?x)").unwrap_err();
        assert_eq!(dup.code, DiagCode::DuplicatePatternVar);

        let unbound = lex.load_source(&mut a, "(rule (bad ?x) ?y)").unwrap_err();
        assert_eq!(unbound.code, DiagCode::UnboundVar);
    }

    #[test]
    fn fractal_handle_capability_firewall_and_fuel_conservation() {
        let mut a = Arena::new();
        let mut lex = Lexicon::new();
        lex.load_source(
            &mut a,
            r#"
            (rule (child_task ?path)
              (str_cat "read:" (perform fs_read ?path)))

            ; firewall handler only permits /safe/ paths; denies everything else
            (rule (firewall (fs_read ?p) ?k)
              (if (str_starts_with ?p "/safe/")
                (match (perform fs_read ?p)
                  (case ?reply (handle (resume ?k ?reply) 500 firewall)))
                (denied ?p)))

            (rule (run_sandboxed ?path)
              (handle (child_task ?path) 500 firewall))
            "#,
        )
        .unwrap();

        // 1. blocked path: never reaches outer host!
        let expr_bad = parse_term(&mut a, r#"(run_sandboxed "/etc/passwd")"#).unwrap();
        let mut fuel = Fuel::new(2000);
        let out = eval(&mut a, &lex, expr_bad, &mut fuel);
        match out {
            Outcome::Done(v) => assert_eq!(print_term(&a, v), r#"(denied "/etc/passwd")"#),
            other => panic!("expected denied done, got {:?}", other),
        }

        // 2. allowed path: passes through firewall to outer host and resumes child cleanly!
        let expr_ok = parse_term(&mut a, r#"(run_sandboxed "/safe/note.txt")"#).unwrap();
        let trace = run_and_record(&mut a, &lex, expr_ok, 2000, |arena, eff| {
            assert_eq!(print_term(arena, eff), r#"(fs_read "/safe/note.txt")"#);
            Ok(arena.mk_str("hello-nacre")?.0)
        })
        .unwrap();

        assert_eq!(
            trace.outcome,
            TraceOutcome::Done {
                value_hash: trace.outcome_hash().unwrap(),
                value_sexpr: String::from(r#"(ok "read:hello-nacre")"#),
            }
        );

        // serialize -> deserialize -> bit-for-bit offline replay in brand new arena!
        let wire = trace.encode_text();
        let decoded = Trace::decode_text(&wire).unwrap();
        let mut fresh_arena = Arena::new();
        let mut fresh_lex = Lexicon::new();
        fresh_lex
            .load_source(
                &mut fresh_arena,
                r#"
                (rule (child_task ?path)
                  (str_cat "read:" (perform fs_read ?path)))
                (rule (firewall (fs_read ?p) ?k)
                  (if (str_starts_with ?p "/safe/")
                    (match (perform fs_read ?p)
                      (case ?reply (handle (resume ?k ?reply) 500 firewall)))
                    (denied ?p)))
                (rule (run_sandboxed ?path)
                  (handle (child_task ?path) 500 firewall))
                "#,
            )
            .unwrap();
        replay_trace(&mut fresh_arena, &fresh_lex, &decoded).unwrap();
    }

    #[test]
    fn prompt_injection_proof_continuation_reply() {
        // if an untrusted llm returns code `(add 1 2)`, plugging it into `_` must treat it as data!
        let mut a = Arena::new();
        let mut lex = Lexicon::new();
        lex.load_source(&mut a, "(rule (ask) (term_tag (perform llm_raw)))")
            .unwrap();
        let entry = parse_term(&mut a, "(ask)").unwrap();
        let trace = run_and_record(&mut a, &lex, entry, 1000, |arena, _| {
            parse_term(arena, "(add 1 2)")
        })
        .unwrap();
        // tag must be `add` (the data term was NOT executed into `3`!)
        match trace.outcome {
            TraceOutcome::Done { value_sexpr, .. } => assert_eq!(value_sexpr, "add"),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn end_to_end_llm_to_reflex_crystallization_and_time_travel() {
        let mut a = Arena::new();
        let mut base_lex = Lexicon::new();
        // v0: agent delegates triage to an expensive external llm capability
        base_lex
            .load_source(
                &mut a,
                r#"
                (rule (triage ?msg)
                  (perform llm_classify ?msg))

                (rule (route ?msg)
                  (match (triage ?msg)
                    (case urgent (escalate ?msg))
                    (case billing (queue_billing ?msg))
                    (case _ (queue_general ?msg))))
                "#,
            )
            .unwrap();

        let tickets = vec![
            r#"(route "outage: production db down")"#,
            r#"(route "invoice #402 duplicate charge")"#,
            r#"(route "how do i reset my theme?")"#,
            r#"(route "outage: api 503 errors")"#,
        ];

        let mut traces = Vec::new();
        for src in &tickets {
            let entry = parse_term(&mut a, src).unwrap();
            let tr = run_and_record(&mut a, &base_lex, entry, 2000, |arena, eff| {
                // simulated expensive llm oracle
                let txt = match arena.node(eff) {
                    Node::App(_, args) => match arena.node(args[0]) {
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
                let sym = arena.intern_sym(label);
                Ok(arena.mk_sym(sym)?.0)
            })
            .unwrap();
            traces.push(tr);
        }

        // time-travel fork: replay trace 0 at event 0 with a different classification!
        let alt_sym = a.intern_sym("billing");
        let alt_reply = a.mk_sym(alt_sym).unwrap().0;
        let forked = fork_from_event(&mut a, &base_lex, &traces[0], 0, alt_reply, |_, _| {
            unreachable!("no further effects")
        })
        .unwrap();
        match &forked.outcome {
            TraceOutcome::Done { value_sexpr, .. } => {
                assert_eq!(value_sexpr, r#"(queue_billing "outage: production db down")"#);
            }
            other => panic!("unexpected fork outcome {:?}", other),
        }

        // bad reflex that hallucinates on billing -> MUST BE REJECTED
        let bad_reflex = r#"
            (rule (triage ?msg)
              (if (str_contains ?msg "outage") urgent general))
        "#;
        let rej = crystallize_from_source(&mut a, &base_lex, &traces, bad_reflex).unwrap_err();
        assert_eq!(rej.code, DiagCode::ReplayDivergence);

        // capability-escalating reflex -> MUST BE REJECTED
        let evil_reflex = r#"
            (rule (triage ?msg) (perform exfiltrate_net ?msg))
        "#;
        let esc = crystallize_from_source(&mut a, &base_lex, &traces, evil_reflex).unwrap_err();
        assert_eq!(esc.code, DiagCode::CapabilityEscalation);

        // good pure reflex: 0 llm calls, 100% offline, verified bit-for-bit against all recorded traces!
        let pure_reflex = r#"
            (rule (triage ?msg)
              (if (str_contains ?msg "outage")
                urgent
                (if (str_contains ?msg "invoice")
                  billing
                  general)))
        "#;
        let (crystal_lex, cert) =
            crystallize_from_source(&mut a, &base_lex, &traces, pure_reflex).unwrap();

        assert_eq!(cert.trace_count, 4);
        assert_eq!(cert.base_effects, 4);
        assert_eq!(cert.new_effects, 0);
        assert_eq!(cert.effects_eliminated(), 4);
        assert_eq!(cert.caps_before, vec![String::from("llm_classify")]);
        assert!(cert.is_now_pure());

        // run crystallized lexicon with a host handler that PANICS if any external effect occurs!
        let test_entry = parse_term(&mut a, r#"(route "outage: edge node rebooting")"#).unwrap();
        let offline = run_and_record(&mut a, &crystal_lex, test_entry, 2000, |_, _| {
            panic!("crystallized pure reflex must never invoke host!")
        })
        .unwrap();
        assert_eq!(offline.events.len(), 0);
        match offline.outcome {
            TraceOutcome::Done { value_sexpr, .. } => {
                assert_eq!(value_sexpr, r#"(escalate "outage: edge node rebooting")"#);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn autonomous_reflex_synthesis_zero_llm() {
        use crate::synthesize::auto_crystallize;

        let mut a = Arena::new();
        let mut base_lex = Lexicon::new();
        base_lex
            .load_source(
                &mut a,
                r#"
                (rule (triage ?msg) (perform llm_classify ?msg))
                (rule (handle_ticket ?msg)
                  (match (triage ?msg)
                    (case urgent (page_oncall ?msg))
                    (case billing (refund_queue ?msg))
                    (case _ (inbox ?msg))))
                "#,
            )
            .unwrap();

        let tickets = [
            r#"(handle_ticket "outage: db primary unreachable")"#,
            r#"(handle_ticket "outage: eu edge 503")"#,
            r#"(handle_ticket "invoice #102 charged twice")"#,
            r#"(handle_ticket "invoice #998 pdf missing")"#,
            r#"(handle_ticket "how to export csv?")"#,
            r#"(handle_ticket "feature request: dark theme")"#,
        ];

        let mut traces = Vec::new();
        for src in tickets {
            let entry = parse_term(&mut a, src).unwrap();
            let tr = run_and_record(&mut a, &base_lex, entry, 2000, |arena, eff| {
                let txt = match arena.node(eff) {
                    Node::App(_, args) => match arena.node(args[0]) {
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
                let s = arena.intern_sym(label);
                Ok(arena.mk_sym(s)?.0)
            })
            .unwrap();
            traces.push(tr);
        }

        // autonomous synthesis with NO hand-written candidate rule!
        let crystal = auto_crystallize(&mut a, &base_lex, &traces).unwrap();
        assert_eq!(crystal.target_head, "triage");
        assert_eq!(crystal.replaced_cap, "llm_classify");
        assert_eq!(crystal.cert.effects_eliminated(), 6);
        assert!(crystal.cert.is_now_pure());

        // unseen inputs execute offline with 0 host calls
        let unseen = parse_term(&mut a, r#"(handle_ticket "outage: cache cluster down")"#).unwrap();
        let tr = run_and_record(&mut a, &crystal.lexicon, unseen, 2000, |_, _| {
            panic!("synthesized pure reflex must never invoke host")
        })
        .unwrap();
        match tr.outcome {
            TraceOutcome::Done { value_sexpr, .. } => {
                assert_eq!(value_sexpr, r#"(page_oncall "outage: cache cluster down")"#);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn tier2_wasm_reflex_differential_oracle() {
        use crate::wasm_emit::{
            compile_pure_i64_reflex, exec_wasm_reflex, WASM_STATUS_DIV_ZERO, WASM_STATUS_EXHAUSTED,
            WASM_STATUS_OK,
        };

        let mut a = Arena::new();
        let mut lex = Lexicon::new();
        lex.load_source(
            &mut a,
            r#"
            (rule (fib 0) 0)
            (rule (fib 1) 1)
            (rule (fib ?n) (add (fib (sub ?n 1)) (fib (sub ?n 2))))

            (rule (safe_div ?x ?y) (div ?x ?y))

            (rule (impure ?x) (perform net_log ?x))
            "#,
        )
        .unwrap();

        // 1. pure recursive fib -> real wasm 1.0 binary -> differential oracle vs symbolic eval
        let fib_sym = a.lookup_sym("fib").unwrap();
        let reflex = compile_pure_i64_reflex(&a, &lex, fib_sym).unwrap();
        assert!(reflex.wasm_bytes.starts_with(b"\x00asm\x01\x00\x00\x00"));
        assert!(reflex.wasm_bytes.len() < 400);

        for n in 0..=11i64 {
            let expr = parse_term(&mut a, &alloc::format!("(fib {})", n)).unwrap();
            let mut fuel = Fuel::new(50_000);
            let sym_val = match eval(&mut a, &lex, expr, &mut fuel) {
                Outcome::Done(v) => match a.node(v) {
                    Node::Int(i) => *i,
                    other => panic!("expected int, got {:?}", other),
                },
                other => panic!("symbolic eval failed: {:?}", other),
            };
            let wasm_res = exec_wasm_reflex(&reflex.wasm_bytes, &[n], 50_000).unwrap();
            assert_eq!(wasm_res.status, WASM_STATUS_OK);
            assert_eq!(wasm_res.value, sym_val, "parity mismatch for fib({})", n);
        }

        // 2. fuel exhaustion in wasm reflex never traps
        let ex = exec_wasm_reflex(&reflex.wasm_bytes, &[15], 10).unwrap();
        assert_eq!(ex.status, WASM_STATUS_EXHAUSTED);

        // 3. division by zero in wasm reflex never traps
        let div_sym = a.lookup_sym("safe_div").unwrap();
        let div_reflex = compile_pure_i64_reflex(&a, &lex, div_sym).unwrap();
        let div_ok = exec_wasm_reflex(&div_reflex.wasm_bytes, &[42, 6], 100).unwrap();
        assert_eq!(div_ok.status, WASM_STATUS_OK);
        assert_eq!(div_ok.value, 7);
        let div_zero = exec_wasm_reflex(&div_reflex.wasm_bytes, &[42, 0], 100).unwrap();
        assert_eq!(div_zero.status, WASM_STATUS_DIV_ZERO);

        // 4. effectful rule rejected by pure wasm compiler
        let impure_sym = a.lookup_sym("impure").unwrap();
        let err = compile_pure_i64_reflex(&a, &lex, impure_sym).unwrap_err();
        assert_eq!(err.code, DiagCode::CapabilityEscalation);
    }

    #[test]
    fn hybrid_myelination_and_portable_ncrystal_bundle_verification() {
        use crate::bundle::CrystalBundle;
        use crate::synthesize::{auto_crystallize_with_mode, SynthMode};

        let mut a = Arena::new();
        let mut base_lex = Lexicon::new();
        base_lex
            .load_source(
                &mut a,
                r#"
                (rule (triage ?msg) (perform llm_classify ?msg))
                (rule (route ?msg)
                  (match (triage ?msg)
                    (case urgent (escalate ?msg))
                    (case billing (queue_billing ?msg))
                    (case _ (queue_general ?msg))))
                "#,
            )
            .unwrap();

        let tickets = [
            (r#"(route "outage: db primary down")"#, "urgent"),
            (r#"(route "outage: eu edge 503")"#, "urgent"),
            (r#"(route "invoice #102 charged twice")"#, "billing"),
            (r#"(route "invoice #998 pdf missing")"#, "billing"),
            (r#"(route "custom enterprise sla inquiry")"#, "general"),
        ];

        let mut traces = Vec::new();
        for (src, label) in tickets {
            let entry = parse_term(&mut a, src).unwrap();
            let tr = run_and_record(&mut a, &base_lex, entry, 2000, |arena, _| {
                let s = arena.intern_sym(label);
                Ok(arena.mk_sym(s)?.0)
            })
            .unwrap();
            traces.push(tr);
        }

        // hybrid guarded mode (min_support = 2): crystallizes outage & invoice,
        // keeps llm_classify fallback for novel/rare enterprise sla!
        let hybrid = auto_crystallize_with_mode(
            &mut a,
            &base_lex,
            &traces,
            SynthMode::HybridGuarded { min_support: 2 },
        )
        .unwrap();
        assert_eq!(hybrid.cert.base_effects, 5);
        assert_eq!(hybrid.cert.new_effects, 1); // 4/5 llm calls eliminated, 1 novel escalated!
        assert_eq!(hybrid.cert.effects_eliminated(), 4);

        // unseen outage ticket executes offline with 0 llm calls
        let known = parse_term(&mut a, r#"(route "outage: worker crash")"#).unwrap();
        let mut fuel = Fuel::new(2000);
        match eval(&mut a, &hybrid.lexicon, known, &mut fuel) {
            Outcome::Done(v) => assert_eq!(print_term(&a, v), r#"(escalate "outage: worker crash")"#),
            other => panic!("expected offline done, got {:?}", other),
        }

        // unseen novel ticket safely yields back to llm_classify instead of guessing!
        let novel = parse_term(&mut a, r#"(route "partnership with university lab")"#).unwrap();
        let mut fuel2 = Fuel::new(2000);
        match eval(&mut a, &hybrid.lexicon, novel, &mut fuel2) {
            Outcome::Yield { effect, .. } => {
                assert_eq!(
                    print_term(&a, effect),
                    r#"(llm_classify "partnership with university lab")"#
                );
            }
            other => panic!("expected safe fallback yield, got {:?}", other),
        }

        // package as portable `.ncrystal` bundle -> encode -> decode -> verify!
        let full_src = hybrid.lexicon.to_source(&a);
        let bundle = CrystalBundle::new("support-triage", full_src, hybrid.cert, None);
        let wire = bundle.encode_text();
        let decoded = CrystalBundle::decode_text(&wire).unwrap();
        let info = decoded.verify().unwrap();
        assert_eq!(info.name, "support-triage");
        assert_eq!(info.effects_eliminated, 4);
        assert_eq!(info.static_caps, vec![String::from("llm_classify")]);

        // tampering with a single character in the bundle MUST fail verification!
        let tampered = wire.replace("escalate", "exfiltrate");
        assert!(CrystalBundle::decode_text(&tampered).is_err());
    }

    #[test]
    fn verifiable_5_stage_hill_climb_sum_to_and_prime_falsification_control() {
        use crate::evolve::{eval_held_out_int, hill_climb_integer_task, ClimbStage};
        use crate::wasm_emit::{exec_wasm_reflex, WASM_STATUS_OK};

        // 1. sum_to(n) must genuinely climb all 5 physical stages from scratch:
        //    gen0_oracle -> gen1_hybrid -> gen2_pure_recursive -> gen3_pure_closed_form -> gen4_wasm
        let mut a = Arena::new();
        let mut base = Lexicon::new();
        base.load_source(&mut a, "(rule (solve ?p0) (perform oracle ?p0))")
            .unwrap();

        let mut traces = Vec::new();
        for n in 0..=6i64 {
            let entry = parse_term(&mut a, &alloc::format!("(solve {})", n)).unwrap();
            let tr = run_and_record(&mut a, &base, entry, 50_000, |ar, eff| {
                let x = match ar.node(eff) {
                    Node::App(_, args) => match ar.node(args[0]) {
                        Node::Int(v) => *v,
                        _ => 0,
                    },
                    _ => 0,
                };
                Ok(ar.mk_int(x * (x + 1) / 2)?.0)
            })
            .unwrap();
            traces.push(tr);
        }

        let report = hill_climb_integer_task(&mut a, &base, &traces, "solve").unwrap();
        assert_eq!(report.final_stage(), ClimbStage::Gen4WasmReflex);
        // verify it climbed through BOTH Gen2 recursive AND Gen3 O(1) closed-form fuel collapse!
        let gen2 = report
            .history
            .iter()
            .find(|g| g.stage == ClimbStage::Gen2PureRecursive)
            .expect("expected gen2 recursive stage");
        let gen3 = report
            .history
            .iter()
            .find(|g| g.stage == ClimbStage::Gen3PureClosedForm)
            .expect("expected gen3 closed-form superoptimization stage");
        assert!(
            gen3.train_fuel < gen2.train_fuel,
            "gen3 closed form must strictly reduce fuel vs gen2 recursive ({} vs {})",
            gen3.train_fuel,
            gen2.train_fuel
        );

        // unseen held-out test points (n = 10, 25, 50)
        let held_out = vec![
            (vec![10], 55),
            (vec![25], 325),
            (vec![50], 1275),
        ];
        let ho = eval_held_out_int(&mut a, &report.final_lexicon, "solve", &held_out, 50_000);
        assert_eq!(ho.offline_exact, 3);
        assert_eq!(ho.offline_wrong, 0);

        let wf = report.wasm_reflex.as_ref().unwrap();
        let r50 = exec_wasm_reflex(&wf.wasm_bytes, &[50], 50_000).unwrap();
        assert_eq!(r50.status, WASM_STATUS_OK);
        assert_eq!(r50.value, 1275);

        // 2. falsification control: primality cannot be expressed by a small closed arithmetic formula.
        //    must stop safely at gen1_hybrid_table with ZERO wrong answers on unseen primes!
        let mut p_traces = Vec::new();
        let is_prime = |n: i64| -> i64 {
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
        };
        for n in 2..=11i64 {
            let entry = parse_term(&mut a, &alloc::format!("(solve {})", n)).unwrap();
            let tr = run_and_record(&mut a, &base, entry, 50_000, |ar, eff| {
                let x = match ar.node(eff) {
                    Node::App(_, args) => match ar.node(args[0]) {
                        Node::Int(v) => *v,
                        _ => 0,
                    },
                    _ => 0,
                };
                Ok(ar.mk_int(is_prime(x))?.0)
            })
            .unwrap();
            p_traces.push(tr);
        }
        let p_report = hill_climb_integer_task(&mut a, &base, &p_traces, "solve").unwrap();
        assert_eq!(p_report.final_stage(), ClimbStage::Gen1HybridTable);
        let p_ho = eval_held_out_int(
            &mut a,
            &p_report.final_lexicon,
            "solve",
            &[(vec![13], 1), (vec![15], 0), (vec![17], 1), (vec![21], 0)],
            50_000,
        );
        assert_eq!(p_ho.offline_wrong, 0);
        assert_eq!(p_ho.escalated_safe, 4);
    }

    #[test]
    fn nanocode_jsonl_journal_bridge_end_to_end() {
        use crate::nanocode_bridge::{
            crystallize_from_nanocode_jsonl, encode_nanocode_journal_jsonl,
        };
        use crate::synthesize::SynthMode;

        let mut jsonl = encode_nanocode_journal_jsonl(&[
            ("llm_classify", "token exchange failed 403", "auth"),
            ("llm_classify", "oauth login token expired", "auth"),
            ("llm_classify", "playwright browser tab crash", "browser"),
            ("llm_classify", "chrome browser headless timeout", "browser"),
            ("llm_classify", "nix flake cli install flag", "cli"),
        ]);
        // inject real nanocode JS non-determinism entries (clock/random) that must be ignored
        jsonl.push_str("{\"kind\":\"clock\",\"value\":1700000000.0}\n");
        jsonl.push_str("{\"kind\":\"random\",\"value\":0.4219}\n");

        let (mut arena, summary, _traces, crystal) = crystallize_from_nanocode_jsonl(
            &jsonl,
            "llm_classify",
            SynthMode::HybridGuarded { min_support: 2 },
        )
        .unwrap();

        assert_eq!(summary.matched_calls, 5);
        assert_eq!(summary.js_nondet_entries_skipped, 2);
        assert_eq!(crystal.cert.base_effects, 5);
        assert_eq!(crystal.cert.new_effects, 1); // 4/5 eliminated, 1 rare escalated safely

        // unseen auth issue executes offline with 0 llm calls
        let unseen = parse_term(&mut arena, r#"(dispatch "sso token refresh error")"#).unwrap();
        let mut fuel = Fuel::new(2000);
        match eval(&mut arena, &crystal.lexicon, unseen, &mut fuel) {
            Outcome::Done(v) => assert_eq!(print_term(&arena, v), "auth"),
            other => panic!("expected offline auth, got {:?}", other),
        }
    }

    #[test]
    fn pt_mcmc_beats_greedy_and_red_queen_hardens_without_autoimmune() {
        use crate::coev::{run_attacker_ablation, run_red_queen_coevolution, DefenderGen};
        use crate::pt_mcmc::SearchAlgo;

        // 1. red-queen co-evolution: must harden across generations, stay 100% alive,
        //    reject overly broad autoimmune antibodies (including dual-use base64 on model_1),
        //    and maintain 0 regression leaks across the entire fossil record!
        let (rounds, final_def) = run_red_queen_coevolution(0, 10, 4000, 0x1337_cafe);
        assert!(rounds.len() >= 8, "expected multi-generation hardening trajectory");
        for r in &rounds {
            assert_eq!(
                r.alive_passed, r.alive_total,
                "autoimmune breach at gen {}",
                r.generation
            );
        }
        assert!(
            final_def.autoimmune_rejections > 0,
            "alive suite must reject overly broad autoimmune antibodies"
        );
        for fossil in &final_def.fossils {
            assert!(
                final_def.blocked_by_hard_antibody(fossil),
                "regression leak on fossil {:?}",
                fossil
            );
        }

        // dual-use model_1 must also harden cleanly without breaking benign `base64 tutorial`
        let (_r1, m1_final) = run_red_queen_coevolution(1, 10, 4000, 0xbeef_03e5);
        assert_eq!(m1_final.verify_alive_in_nacre(), (12, 12));
        assert_eq!(m1_final.antibodies.len(), 8);

        // 2. 4-way attacker ablation on hardened Gen 4 checkpoint:
        //    as refusal walls compound, PT-MCMC + Genetic outperforms Random, Greedy, and Single-Temp SA!
        let (_, hardened4) = run_red_queen_coevolution(0, 4, 4000, 0x1337_cafe);
        let rows = run_attacker_ablation(&hardened4, 3000, 25);
        let random_row = rows.iter().find(|r| r.algo == SearchAlgo::Random).unwrap();
        let greedy_row = rows
            .iter()
            .find(|r| r.algo == SearchAlgo::GreedyHillClimb)
            .unwrap();
        let sa_row = rows
            .iter()
            .find(|r| r.algo == SearchAlgo::SingleTempSA)
            .unwrap();
        let pt_row = rows
            .iter()
            .find(|r| r.algo == SearchAlgo::ParallelTemperingGenetic)
            .unwrap();

        assert!(pt_row.breaches > random_row.breaches);
        assert_eq!(pt_row.breaches, 25);
        assert!(
            pt_row.avg_evals_when_breached < greedy_row.avg_evals_when_breached,
            "pt_mcmc ({}) should beat greedy ({}) on hardened gen 4 checkpoint",
            pt_row.avg_evals_when_breached,
            greedy_row.avg_evals_when_breached
        );
        assert!(
            pt_row.avg_evals_when_breached < sa_row.avg_evals_when_breached,
            "pt_mcmc ({}) should beat single-temp SA ({}) on hardened gen 4 checkpoint",
            pt_row.avg_evals_when_breached,
            sa_row.avg_evals_when_breached
        );
        let _ = DefenderGen::gen0(0);
    }

    #[test]
    fn security_control_matrix_proves_naked_fails_and_nacre_holds() {
        use crate::security_bench::run_security_control_bench;

        let report = run_security_control_bench();
        assert_eq!(report.static_classes.len(), 5);
        for row in &report.static_classes {
            assert_eq!(
                row.naked_breaches, row.probes,
                "naked control must fail on {}",
                row.class_name
            );
            assert!(
                row.naive_breaches > 0,
                "naive guard should still leak on {}",
                row.class_name
            );
            assert_eq!(
                row.nacre_breaches, 0,
                "nacre kernel must hold 0 breaches on {}",
                row.class_name
            );
        }

        // adaptive control arms:
        // arm0 (naked) breaches immediately; arm1 (naive blocklist) suffers autoimmune collapse;
        // arm2 (soft prompt cap) suffers regression leaks; arm3 (nacre) holds 12/12 alive & 0 leaks!
        let arm0 = &report.adaptive_arms[0];
        let arm1 = &report.adaptive_arms[1];
        let arm2 = &report.adaptive_arms[2];
        let arm3 = &report.adaptive_arms[3];

        assert!(arm0.pt_breached_final);
        assert!(arm1.final_alive_ok < arm1.final_alive_total, "naive blocklist must collapse alive");
        assert!(arm2.regression_leaks > 0, "capped soft prompt must leak old fossils");
        assert!(arm2.replay_llm_calls > 0);
        assert_eq!(arm3.final_alive_ok, arm3.final_alive_total);
        assert_eq!(arm3.regression_leaks, 0);
        assert!(!arm3.pt_breached_final);
        assert_eq!(arm3.replay_llm_calls, 0);
    }

    trait OutcomeHashExt {
        fn outcome_hash(&self) -> Option<crate::hash::Hash256>;
    }
    impl OutcomeHashExt for Trace {
        fn outcome_hash(&self) -> Option<crate::hash::Hash256> {
            match &self.outcome {
                TraceOutcome::Done { value_hash, .. } => Some(*value_hash),
                _ => None,
            }
        }
    }
}
