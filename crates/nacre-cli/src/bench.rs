//! real 2-domain verifiable hill-climb benchmark & ablation suite (zero fake data, zero hints).
//!
//! domain a: 12 provable algorithmic synthesis & superoptimization tasks with strictly disjoint
//!           train journals vs. unseen held-out test inputs (including 1 hard falsification control).
//! domain b: 60-event incremental multi-class streaming benchmark (32 train / 28 held-out)
//!           comparing premature pure crystallization vs. hybrid guarded myelination.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use nacre_core::arena::{Arena, Node};
use nacre_core::eval::{eval, Outcome};
use nacre_core::evolve::{eval_held_out_int, hill_climb_integer_task, ClimbStage};
use nacre_core::fuel::Fuel;
use nacre_core::journal::run_and_record;
use nacre_core::lexicon::Lexicon;
use nacre_core::nanocode_bridge::{crystallize_from_nanocode_jsonl, encode_nanocode_journal_jsonl};
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize_with_mode, SynthMode};
use nacre_core::wasm_emit::{exec_wasm_reflex, WASM_STATUS_OK};

struct IntTask {
    name: &'static str,
    arity: usize,
    oracle: fn(&[i64]) -> i64,
    train: Vec<Vec<i64>>,
    held_out: Vec<Vec<i64>>,
    expect_expressible: bool,
}

fn is_prime(n: i64) -> i64 {
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

fn build_domain_a_tasks() -> Vec<IntTask> {
    vec![
        IntTask {
            name: "affine_3x_p7",
            arity: 1,
            oracle: |xs| 3 * xs[0] + 7,
            train: (0..=5).map(|x| vec![x]).collect(),
            held_out: vec![vec![-10], vec![11], vec![25], vec![100]],
            expect_expressible: true,
        },
        IntTask {
            name: "quad_x2_px",
            arity: 1,
            oracle: |xs| xs[0] * xs[0] + xs[0],
            train: (0..=5).map(|x| vec![x]).collect(),
            held_out: vec![vec![-7], vec![9], vec![20], vec![50]],
            expect_expressible: true,
        },
        IntTask {
            name: "sum_to_n",
            arity: 1,
            oracle: |xs| xs[0] * (xs[0] + 1) / 2,
            train: (0..=6).map(|x| vec![x]).collect(),
            held_out: vec![vec![10], vec![15], vec![25], vec![50]],
            expect_expressible: true,
        },
        IntTask {
            name: "factorial",
            arity: 1,
            oracle: |xs| (1..=xs[0]).product(),
            train: (0..=5).map(|x| vec![x]).collect(),
            held_out: vec![vec![6], vec![7], vec![8], vec![10]],
            expect_expressible: true,
        },
        IntTask {
            name: "fibonacci",
            arity: 1,
            oracle: |xs| {
                let (mut a, mut b) = (0i64, 1i64);
                for _ in 0..xs[0] {
                    let t = a + b;
                    a = b;
                    b = t;
                }
                a
            },
            train: (0..=6).map(|x| vec![x]).collect(),
            held_out: vec![vec![8], vec![10], vec![12]],
            expect_expressible: true,
        },
        IntTask {
            name: "abs_val",
            arity: 1,
            oracle: |xs| xs[0].abs(),
            train: vec![vec![-5], vec![-2], vec![-1], vec![0], vec![1], vec![3], vec![6]],
            held_out: vec![vec![-99], vec![-12], vec![7], vec![42]],
            expect_expressible: true,
        },
        IntTask {
            name: "sign_fn",
            arity: 1,
            oracle: |xs| xs[0].signum(),
            train: vec![vec![-5], vec![-2], vec![-1], vec![0], vec![1], vec![3], vec![6]],
            held_out: vec![vec![-40], vec![-1], vec![0], vec![17], vec![999]],
            expect_expressible: true,
        },
        IntTask {
            name: "clamp_0_10",
            arity: 1,
            oracle: |xs| xs[0].clamp(0, 10),
            train: vec![
                vec![-5],
                vec![-1],
                vec![0],
                vec![3],
                vec![7],
                vec![10],
                vec![12],
                vec![20],
            ],
            held_out: vec![vec![-50], vec![1], vec![5], vec![9], vec![11], vec![100]],
            expect_expressible: true,
        },
        IntTask {
            name: "is_even",
            arity: 1,
            oracle: |xs| if xs[0] % 2 == 0 { 1 } else { 0 },
            train: (0..=7).map(|x| vec![x]).collect(),
            held_out: vec![vec![10], vec![13], vec![42], vec![99], vec![1000]],
            expect_expressible: true,
        },
        IntTask {
            name: "collatz_step",
            arity: 1,
            oracle: |xs| if xs[0] % 2 == 0 { xs[0] / 2 } else { 3 * xs[0] + 1 },
            train: (1..=8).map(|x| vec![x]).collect(),
            held_out: vec![vec![9], vec![10], vec![15], vec![22], vec![27]],
            expect_expressible: true,
        },
        IntTask {
            name: "max2",
            arity: 2,
            oracle: |xs| xs[0].max(xs[1]),
            train: vec![
                vec![1, 5],
                vec![5, 1],
                vec![3, 3],
                vec![-2, 4],
                vec![7, -1],
                vec![0, 2],
            ],
            held_out: vec![vec![-10, -3], vec![42, 17], vec![8, 8], vec![0, -5]],
            expect_expressible: true,
        },
        // honest falsification control: primality is NOT expressible in a depth-2 fixed-op formula
        IntTask {
            name: "prime_ctrl",
            arity: 1,
            oracle: |xs| is_prime(xs[0]),
            train: (2..=11).map(|x| vec![x]).collect(),
            held_out: vec![vec![13], vec![14], vec![15], vec![17], vec![21], vec![23]],
            expect_expressible: false,
        },
    ]
}

pub fn run_bench() -> Result<(), String> {
    println!("=== nacre verifiable hill-climb & ablation benchmark ===");
    println!("(deterministic, zero rng, zero floats, zero hints — raw measured outputs)");
    println!();

    run_domain_a()?;
    println!();
    run_domain_b()?;
    println!();
    run_domain_c_real_codex_issues()?;
    Ok(())
}

fn run_domain_a() -> Result<(), String> {
    println!("--- domain a: algorithmic synthesis & superoptimization (12 tasks, disjoint held-out) ---");
    println!(
        "{:<14} {:<19} {:>4} {:>8} {:>9} {:>10} {:>10} {:>10}",
        "task", "final_stage", "gens", "evald", "pruned", "ho_exact", "ho_safe", "wasm"
    );

    let tasks = build_domain_a_tasks();
    let mut expressible_total = 0usize;
    let mut expressible_solved = 0usize;
    let mut total_ho_wrong = 0usize;
    let mut total_wasm_ok = 0usize;
    let mut sum_to_trace_detail: Vec<String> = Vec::new();

    for task in &tasks {
        let mut arena = Arena::new();
        let mut base_lex = Lexicon::new();
        let params = if task.arity == 1 { "?p0" } else { "?p0 ?p1" };
        let base_src = format!("(rule (solve {p}) (perform oracle {p}))", p = params);
        base_lex
            .load_source(&mut arena, &base_src)
            .map_err(|d| format!("{}", d))?;

        // record real durable merkle traces on train split ONLY
        let mut train_traces = Vec::new();
        for xs in &task.train {
            let arg_s: Vec<String> = xs.iter().map(|v| format!("{}", v)).collect();
            let entry = parse_term(&mut arena, &format!("(solve {})", arg_s.join(" ")))
                .map_err(|d| format!("{}", d))?;
            let oracle_fn = task.oracle;
            let tr = run_and_record(&mut arena, &base_lex, entry, 50_000, |a, eff| {
                let args: Vec<i64> = match a.node(eff) {
                    Node::App(_, eargs) => eargs
                        .iter()
                        .map(|&id| match a.node(id) {
                            Node::Int(v) => *v,
                            _ => 0,
                        })
                        .collect(),
                    _ => vec![],
                };
                let y = oracle_fn(&args);
                Ok(a.mk_int(y)?.0)
            })
            .map_err(|d| format!("{}", d))?;
            train_traces.push(tr);
        }

        let held_out_pairs: Vec<(Vec<i64>, i64)> = task
            .held_out
            .iter()
            .map(|xs| (xs.clone(), (task.oracle)(xs)))
            .collect();

        // run real verifier-gated hill-climb from recorded traces alone!
        let report = hill_climb_integer_task(&mut arena, &base_lex, &train_traces, "solve")
            .map_err(|d| format!("{}", d))?;

        let ho = eval_held_out_int(&mut arena, &report.final_lexicon, "solve", &held_out_pairs, 100_000);
        total_ho_wrong += ho.offline_wrong + ho.faults;

        // check wasm differential parity on ALL strictly unseen held-out inputs!
        let wasm_str = if let Some(ref wf) = report.wasm_reflex {
            let mut parity_hits = 0usize;
            for (xs, expected) in &held_out_pairs {
                if let Ok(res) = exec_wasm_reflex(&wf.wasm_bytes, xs, 100_000) {
                    if res.status == WASM_STATUS_OK && res.value == *expected {
                        parity_hits += 1;
                    }
                }
            }
            if parity_hits == held_out_pairs.len() {
                total_wasm_ok += 1;
                format!("{}b ({}/{})", wf.wasm_bytes.len(), parity_hits, held_out_pairs.len())
            } else {
                format!("{}b err", wf.wasm_bytes.len())
            }
        } else {
            String::from("-")
        };

        if task.expect_expressible {
            expressible_total += 1;
            if ho.offline_exact == ho.total && ho.offline_wrong == 0 {
                expressible_solved += 1;
            }
        }

        println!(
            "{:<14} {:<19} {:>4} {:>8} {:>9} {:>4}/{:<5} {:>4}/{:<5} {:>10}",
            task.name,
            report.final_stage().label(),
            report.history.len(),
            report.candidates_evaluated,
            report.candidates_pruned_obs_equiv,
            ho.offline_exact,
            ho.total,
            ho.escalated_safe,
            ho.total,
            wasm_str
        );

        // capture detailed multi-generation hill-climb trajectory for sum_to_n
        if task.name == "sum_to_n" {
            for (gi, step) in report.history.iter().enumerate() {
                // compute held-out fuel at this generation too!
                let mut g_arena = Arena::new();
                let mut g_lex = Lexicon::new();
                g_lex.load_source(&mut g_arena, &step.rule_src).unwrap();
                let g_ho = eval_held_out_int(&mut g_arena, &g_lex, "solve", &held_out_pairs, 100_000);
                sum_to_trace_detail.push(format!(
                    "  gen {}: {:<20} train_eff={:<2} train_fuel={:<5} ho_exact={}/{} ho_fuel={:<5} rule={}",
                    gi,
                    step.stage.label(),
                    step.train_effects,
                    step.train_fuel,
                    g_ho.offline_exact,
                    g_ho.total,
                    g_ho.total_fuel,
                    step.rule_src.replace('\n', " | ")
                ));
            }
            if let Some(ref wf) = report.wasm_reflex {
                let r50 = exec_wasm_reflex(&wf.wasm_bytes, &[50], 100_000).unwrap();
                sum_to_trace_detail.push(format!(
                    "  gen 4: {:<20} wasm_bytes={} wasm(50)={} status={} calls={}",
                    ClimbStage::Gen4WasmReflex.label(),
                    wf.wasm_bytes.len(),
                    r50.value,
                    r50.status,
                    r50.fuel_used
                ));
            }
        }
    }

    println!();
    println!("domain a summary:");
    println!(
        "  expressible tasks solved 100% on unseen held-out: {}/{}",
        expressible_solved, expressible_total
    );
    println!(
        "  total held-out wrong answers across all 12 tasks (incl. prime_ctrl): {}",
        total_ho_wrong
    );
    println!(
        "  tier-2 wasm reflexes passing 100% held-out parity: {}/{}",
        total_wasm_ok, expressible_total
    );

    if !sum_to_trace_detail.is_empty() {
        println!();
        println!("multi-generation climb trajectory (sum_to_n, held-out=[10, 15, 25, 50]):");
        for line in sum_to_trace_detail {
            println!("{}", line);
        }
    }
    Ok(())
}

fn run_domain_b() -> Result<(), String> {
    println!("--- domain b: incremental streaming ablation (32 train -> 28 strictly unseen held-out, 5 classes) ---");

    // 32 deterministic training events + 28 strictly unseen held-out events with shared distractor words
    // ("error", "request", "account", "us-east", "ticket")
    let train_data: &[(&str, &str)] = &[
        ("us-east error: postgres replica down on node 1", "db_outage"),
        ("ticket 101: invoice duplicate charge on card", "billing_dup"),
        ("alert: brute force login failed 40 times account", "auth_breach"),
        ("api error: 429 throttle limit exceeded request", "rate_limit"),
        ("question: how to export csv from dashboard?", "general_help"),
        ("eu-west error: postgres primary timeout node 4", "db_outage"),
        ("ticket 102: invoice double charge for april", "billing_dup"),
        ("security: brute force ssh token compromise", "auth_breach"),
        ("gateway: 429 throttle burst quota hit request", "rate_limit"),
        ("question: where is dark mode setting in account?", "general_help"),
        ("ap-south: postgres disk full replication lag", "db_outage"),
        ("billing: invoice #901 duplicate refund needed", "billing_dup"),
        ("audit: suspicious login brute force alert", "auth_breach"),
        ("edge: 429 throttle retry-after header error", "rate_limit"),
        ("help: how to invite teammate to workspace?", "general_help"),
        ("us-west: postgres connection pool exhausted", "db_outage"),
        ("receipt: invoice #332 billed twice account", "billing_dup"),
        ("alert: brute force api key probe detected", "auth_breach"),
        ("proxy: 429 throttle cap reached on webhook", "rate_limit"),
        ("docs: keyboard shortcuts guide for studio?", "general_help"),
        ("cluster: postgres failover stalled in zone b", "db_outage"),
        ("card: invoice #440 double billing error", "billing_dup"),
        ("iam: brute force password spray attempt", "auth_breach"),
        ("cdn: 429 throttle exceeded per-ip bucket", "rate_limit"),
        ("onboarding: how to connect custom domain?", "general_help"),
        ("db: postgres wal archive error on shard 3", "db_outage"),
        ("stripe: invoice #771 charged two times", "billing_dup"),
        ("soc: brute force credential stuffing wave", "auth_breach"),
        ("worker: 429 throttle backoff triggered", "rate_limit"),
        ("faq: can i download offline backup zip?", "general_help"),
        ("ops: postgres deadlock spike on orders table", "db_outage"),
        ("finance: invoice #882 duplicate debit alert", "billing_dup"),
    ];

    let held_out_data: &[(&str, &str)] = &[
        ("us-east: postgres primary unreachable after deploy", "db_outage"),
        ("eu-central: postgres shard 9 read-only error", "db_outage"),
        ("node-7: postgres checkpoint stall warning", "db_outage"),
        ("zone-c: postgres vacuum blocked long tx", "db_outage"),
        ("ops-9: postgres failover complete with lag", "db_outage"),
        ("ticket 801: invoice #990 charged twice yesterday", "billing_dup"),
        ("ticket 802: invoice #991 duplicate receipt", "billing_dup"),
        ("account: invoice #992 double charge refund", "billing_dup"),
        ("stripe: invoice #993 billed twice on renewal", "billing_dup"),
        ("card: invoice #994 duplicate monthly fee", "billing_dup"),
        ("sec-1: brute force login spike from botnet", "auth_breach"),
        ("sec-2: brute force oauth secret guessing", "auth_breach"),
        ("sec-3: brute force admin portal attempts", "auth_breach"),
        ("sec-4: brute force mfa otp flood detected", "auth_breach"),
        ("sec-5: brute force ssh key scan on bastion", "auth_breach"),
        ("api-1: 429 throttle triggered by batch job", "rate_limit"),
        ("api-2: 429 throttle on search endpoint", "rate_limit"),
        ("api-3: 429 throttle limit hit by client 44", "rate_limit"),
        ("api-4: 429 throttle burst exceeded quota", "rate_limit"),
        ("api-5: 429 throttle retry needed request", "rate_limit"),
        ("user: how do i rename my project folder?", "general_help"),
        ("user: where can i view keyboard shortcuts?", "general_help"),
        ("user: how to switch billing email address?", "general_help"),
        ("user: can i share a read-only link?", "general_help"),
        // 4 genuinely novel / out-of-distribution phrasing cases (no seen keywords!)
        ("enterprise legal review for soc2 addendum", "general_help"),
        ("academic grant inquiry from mit csail", "general_help"),
        ("hardware security module migration question", "general_help"),
        ("custom on-prem airgapped license request", "general_help"),
    ];

    let base_src = r#"
        (rule (classify ?msg) (perform llm_classify ?msg))
        (rule (dispatch ?msg) (classify ?msg))
    "#;

    println!(
        "{:<7} | {:<32} | {:<38}",
        "train_n",
        "pure_offline (no support guard)",
        "hybrid_guarded (min_support=2)"
    );
    println!(
        "{:<7} | {:>9} {:>9} {:>11} | {:>9} {:>9} {:>9} {:>8}",
        "", "ho_exact", "ho_wrong", "oracle_cut", "ho_exact", "ho_safe", "ho_wrong", "off_prec"
    );

    for &k in &[4usize, 8, 12, 16, 24, 32] {
        let mut arena = Arena::new();
        let mut base_lex = Lexicon::new();
        base_lex.load_source(&mut arena, base_src).unwrap();

        let mut traces = Vec::new();
        for &(msg, label) in &train_data[..k] {
            let entry = parse_term(&mut arena, &format!("(dispatch \"{}\")", msg)).unwrap();
            let tr = run_and_record(&mut arena, &base_lex, entry, 5000, |a, _| {
                let s = a.intern_sym(label);
                Ok(a.mk_sym(s)?.0)
            })
            .unwrap();
            traces.push(tr);
        }

        // 1. pure offline mode
        let pure_res = auto_crystallize_with_mode(&mut arena, &base_lex, &traces, SynthMode::PureOffline);
        let (p_exact, p_wrong, p_cut) = match pure_res {
            Ok(ac) => {
                let (ex, wr, _esc) = eval_held_out_labels(&mut arena, &ac.lexicon, held_out_data);
                (ex, wr, held_out_data.len())
            }
            Err(_) => (0, 0, 0),
        };

        // 2. hybrid guarded mode (min_support = 2)
        let hyb_res = auto_crystallize_with_mode(
            &mut arena,
            &base_lex,
            &traces,
            SynthMode::HybridGuarded { min_support: 2 },
        );
        let (h_exact, h_safe, h_wrong) = match hyb_res {
            Ok(ac) => {
                let (ex, wr, esc) = eval_held_out_labels(&mut arena, &ac.lexicon, held_out_data);
                (ex, esc, wr)
            }
            Err(_) => (0, held_out_data.len(), 0),
        };
        let off_total = h_exact + h_wrong;
        let prec_str = if off_total == 0 {
            String::from("n/a")
        } else {
            format!("{}%", (h_exact * 100) / off_total)
        };

        println!(
            "{:<7} | {:>4}/{:<4} {:>9} {:>7}/{:<3} | {:>4}/{:<4} {:>9} {:>9} {:>8}",
            k,
            p_exact,
            held_out_data.len(),
            p_wrong,
            p_cut,
            held_out_data.len(),
            h_exact,
            held_out_data.len(),
            h_safe,
            h_wrong,
            prec_str
        );
    }

    Ok(())
}

fn eval_held_out_labels(
    arena: &mut Arena,
    lex: &Lexicon,
    cases: &[(&str, &str)],
) -> (usize, usize, usize) {
    let mut exact = 0;
    let mut wrong = 0;
    let mut escalated = 0;
    for &(msg, expected) in cases {
        let entry = parse_term(arena, &format!("(dispatch \"{}\")", msg)).unwrap();
        let mut fuel = Fuel::new(5000);
        match eval(arena, lex, entry, &mut fuel) {
            Outcome::Done(v) => {
                if print_term(arena, v) == expected {
                    exact += 1;
                } else {
                    wrong += 1;
                }
            }
            Outcome::Yield { .. } => escalated += 1,
            Outcome::Exhausted { .. } | Outcome::Fault(_) => wrong += 1,
        }
    }
    (exact, wrong, escalated)
}

fn run_domain_c_real_codex_issues() -> Result<(), String> {
    let path = Path::new("benchmarks/codex_issues.tsv");
    if !path.exists() {
        println!("--- domain c: skipped (benchmarks/codex_issues.tsv not found) ---");
        return Ok(());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read codex_issues.tsv failed: {}", e))?;
    let mut by_class: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 3 {
            if let Ok(num) = parts[0].trim().parse::<u64>() {
                by_class
                    .entry(String::from(parts[1].trim()))
                    .or_default()
                    .push((num, String::from(parts[2].trim())));
            }
        }
    }

    // per-class chronological 60/40 split (oldest 60% -> train nanocode journal, newest 40% -> unseen future test)
    let mut train_pairs: Vec<(String, String)> = Vec::new();
    let mut test_pairs: Vec<(String, String)> = Vec::new();
    for (label, mut items) in by_class {
        items.sort_by_key(|(n, _)| *n);
        let split = (items.len() * 60) / 100;
        for (i, (_num, title)) in items.into_iter().enumerate() {
            if i < split {
                train_pairs.push((title, label.clone()));
            } else {
                test_pairs.push((title, label.clone()));
            }
        }
    }

    println!(
        "--- domain c: real external openai/codex github issues ({} train -> {} unseen future issues, 4 real labels) ---",
        train_pairs.len(),
        test_pairs.len()
    );
    println!("    ingested via nanocode-code-mode-engine JSONL journal wire format");

    let wire_refs: Vec<(&str, &str, &str)> = train_pairs
        .iter()
        .map(|(t, l)| ("llm_classify", t.as_str(), l.as_str()))
        .collect();
    let mut nanocode_jsonl = encode_nanocode_journal_jsonl(&wire_refs);
    nanocode_jsonl.push_str("{\"kind\":\"clock\",\"value\":1760000000.0}\n");
    nanocode_jsonl.push_str("{\"kind\":\"random\",\"value\":0.7312}\n");

    println!(
        "{:<24} | {:>10} {:>10} {:>9} {:>10} {:>10}",
        "policy", "off_exact", "off_wrong", "escalated", "off_prec", "llm_saved"
    );

    let policies: &[(&str, SynthMode)] = &[
        ("pure_offline", SynthMode::PureOffline),
        ("hybrid (min_support=2)", SynthMode::HybridGuarded { min_support: 2 }),
        ("hybrid (min_support=3)", SynthMode::HybridGuarded { min_support: 3 }),
        ("hybrid (min_support=4)", SynthMode::HybridGuarded { min_support: 4 }),
        ("hybrid (min_support=6)", SynthMode::HybridGuarded { min_support: 6 }),
    ];

    for &(name, mode) in policies {
        match crystallize_from_nanocode_jsonl(&nanocode_jsonl, "llm_classify", mode) {
            Ok((mut arena, _summary, _traces, crystal)) => {
                let mut exact = 0usize;
                let mut wrong = 0usize;
                let mut escalated = 0usize;
                for (title, expected) in &test_pairs {
                    let escaped = title.replace('\\', "\\\\").replace('"', "\\\"");
                    let expr = parse_term(&mut arena, &format!("(dispatch \"{}\")", escaped))
                        .map_err(|d| format!("{}", d))?;
                    let mut fuel = Fuel::new(10_000);
                    match eval(&mut arena, &crystal.lexicon, expr, &mut fuel) {
                        Outcome::Done(v) => {
                            if print_term(&arena, v) == *expected {
                                exact += 1;
                            } else {
                                wrong += 1;
                            }
                        }
                        Outcome::Yield { .. } => escalated += 1,
                        Outcome::Exhausted { .. } | Outcome::Fault(_) => wrong += 1,
                    }
                }
                let off_total = exact + wrong;
                let prec = if off_total == 0 {
                    String::from("n/a")
                } else {
                    format!("{}%", (exact * 100) / off_total)
                };
                let saved = format!("{}%", (off_total * 100) / test_pairs.len());
                println!(
                    "{:<24} | {:>4}/{:<5} {:>10} {:>4}/{:<4} {:>10} {:>10}",
                    name,
                    exact,
                    test_pairs.len(),
                    wrong,
                    escalated,
                    test_pairs.len(),
                    prec,
                    saved
                );
            }
            Err(d) => {
                println!("{:<24} | rejected: {}", name, d);
            }
        }
    }

    Ok(())
}
