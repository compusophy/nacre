//! zero-dep bridge for `nanocode-code-mode-engine` JSONL journals.
//!
//! ingests `nanocode`'s exact `JournalEntry` JSONL wire format:
//!   {"kind":"call","id":1,"name":"llm_classify","input":"...","host":true}
//!   {"kind":"result","id":1,"encoded":"\"urgent\"","success":true}
//! ignores non-deterministic JS patch entries (`clock`, `monotonic`, `random`, `bytes`, `timeout`, `timer`),
//! converts matched `(call, result)` pairs into cryptographically chained `nacre` merkle traces,
//! and crystallizes mechanically verified zero-token reflexes (`PureOffline` or `HybridGuarded`).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::Arena;
use crate::diag::{Diag, DiagCode};
use crate::journal::{run_and_record, Trace};
use crate::lexicon::Lexicon;
use crate::syntax::parse_term;
use crate::synthesize::{auto_crystallize_with_mode, AutoCrystal, SynthMode};

/// a matched tool/model invocation extracted from a `nanocode` cell journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanocodeToolPair {
    pub id: u64,
    pub tool_name: String,
    pub input_str: String,
    pub output_str: String,
    pub success: bool,
}

/// summary of ingesting a `nanocode` JSONL journal stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanocodeIngestSummary {
    pub total_lines: usize,
    pub matched_calls: usize,
    pub js_nondet_entries_skipped: usize,
    pub pairs: Vec<NanocodeToolPair>,
}

/// parse `nanocode-code-mode-engine` JSONL journal lines with zero external dependencies.
pub fn parse_nanocode_journal_jsonl(jsonl: &str) -> Result<NanocodeIngestSummary, Diag> {
    let mut pending_calls: BTreeMap<u64, (String, String)> = BTreeMap::new();
    let mut pairs = Vec::new();
    let mut total_lines = 0usize;
    let mut js_nondet_entries_skipped = 0usize;

    for raw_line in jsonl.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        total_lines += 1;
        let Some(kind) = extract_json_str(line, "kind") else {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                "nanocode journal line missing \"kind\" field",
            ));
        };

        match kind.as_str() {
            "call" => {
                let id = extract_json_u64(line, "id").ok_or_else(|| {
                    Diag::runtime(DiagCode::JournalHashMismatch, "call entry missing id")
                })?;
                let name = extract_json_str(line, "name").ok_or_else(|| {
                    Diag::runtime(DiagCode::JournalHashMismatch, "call entry missing name")
                })?;
                let input = extract_json_str(line, "input")
                    .or_else(|| extract_json_raw_value(line, "input"))
                    .unwrap_or_default();
                pending_calls.insert(id, (name, input));
            }
            "result" => {
                let id = extract_json_u64(line, "id").ok_or_else(|| {
                    Diag::runtime(DiagCode::JournalHashMismatch, "result entry missing id")
                })?;
                let encoded = extract_json_str(line, "encoded").unwrap_or_default();
                let success = extract_json_bool(line, "success").unwrap_or(true);
                if let Some((tool_name, input_str)) = pending_calls.remove(&id) {
                    // `encoded` in nanocode is JSON-encoded string (e.g. "\"urgent\""), strip outer quotes if present
                    let cleaned_out = unquote_json_if_string(&encoded);
                    if success {
                        pairs.push(NanocodeToolPair {
                            id,
                            tool_name,
                            input_str,
                            output_str: cleaned_out,
                            success,
                        });
                    }
                }
            }
            "clock" | "monotonic" | "random" | "bytes" | "timeout" | "timer" => {
                // JS-specific non-determinism entries not needed in deterministic nacre
                js_nondet_entries_skipped += 1;
            }
            _ => {}
        }
    }

    Ok(NanocodeIngestSummary {
        total_lines,
        matched_calls: pairs.len(),
        js_nondet_entries_skipped,
        pairs,
    })
}

/// encode a batch of `(id, tool_name, input, output)` pairs into `nanocode-code-mode-engine`'s
/// exact `JournalEntry` JSONL wire format (useful for reproducible benchmarking & interop).
pub fn encode_nanocode_journal_jsonl(pairs: &[(&str, &str, &str)]) -> String {
    let mut out = String::new();
    for (idx, &(tool_name, input, output)) in pairs.iter().enumerate() {
        let id = (idx as u64) + 1;
        out.push_str(&format!(
            "{{\"kind\":\"call\",\"id\":{},\"name\":{},\"input\":{},\"host\":true}}\n",
            id,
            json_quote(tool_name),
            json_quote(input)
        ));
        let encoded_inner = json_quote(output);
        out.push_str(&format!(
            "{{\"kind\":\"result\",\"id\":{},\"encoded\":{},\"success\":true}}\n",
            id,
            json_quote(&encoded_inner)
        ));
    }
    out
}

/// ingest a `nanocode` JSONL journal for a specific `tool_name` (e.g. `"llm_classify"`),
/// build canonical `nacre` merkle traces, and synthesize + mechanically verify a reflex!
pub fn crystallize_from_nanocode_jsonl(
    jsonl: &str,
    tool_name: &str,
    mode: SynthMode,
) -> Result<(Arena, NanocodeIngestSummary, Vec<Trace>, AutoCrystal), Diag> {
    let summary = parse_nanocode_journal_jsonl(jsonl)?;
    let filtered: Vec<&NanocodeToolPair> = summary
        .pairs
        .iter()
        .filter(|p| p.tool_name == tool_name)
        .collect();
    if filtered.is_empty() {
        return Err(Diag::runtime(
            DiagCode::EmptyTraceSet,
            format!("no successful '{}' calls found in nanocode journal", tool_name),
        ));
    }

    let cap_sym_name = sanitize_symbol(tool_name);
    let base_src = format!(
        "(rule (reflex ?x) (perform {cap} ?x))\n(rule (dispatch ?x) (reflex ?x))",
        cap = cap_sym_name
    );

    let mut arena = Arena::new();
    let mut base_lex = Lexicon::new();
    base_lex.load_source(&mut arena, &base_src)?;

    let mut traces = Vec::with_capacity(filtered.len());
    for pair in filtered {
        let entry_src = format!("(dispatch {})", nacre_quote(&pair.input_str));
        let entry = parse_term(&mut arena, &entry_src)?;
        let out_sym_name = sanitize_symbol(&pair.output_str);
        let tr = run_and_record(&mut arena, &base_lex, entry, 5000, |a, _| {
            let s = a.intern_sym(&out_sym_name);
            Ok(a.mk_sym(s)?.0)
        })?;
        traces.push(tr);
    }

    let crystal = auto_crystallize_with_mode(&mut arena, &base_lex, &traces, mode)?;
    Ok((arena, summary, traces, crystal))
}

fn sanitize_symbol(s: &str) -> String {
    let mut out = String::new();
    for ch in s.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        String::from("nil")
    } else {
        out
    }
}

fn nacre_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
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
    out.push('"');
    out
}

fn json_quote(s: &str) -> String {
    nacre_quote(s)
}

fn unquote_json_if_string(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        unescape_json_str(&t[1..t.len() - 1])
    } else {
        String::from(t)
    }
}

fn find_key_value_start(json: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{}\":", key);
    let idx = json.find(&needle)?;
    let mut pos = idx + needle.len();
    let bytes = json.as_bytes();
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    Some(pos)
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pos = find_key_value_start(json, key)?;
    let bytes = json.as_bytes();
    if *bytes.get(pos)? != b'"' {
        return None;
    }
    let mut i = pos + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            return Some(unescape_json_str(&json[pos + 1..i]));
        }
        i += 1;
    }
    None
}

fn extract_json_raw_value(json: &str, key: &str) -> Option<String> {
    let pos = find_key_value_start(json, key)?;
    let bytes = json.as_bytes();
    let mut i = pos;
    while i < bytes.len() && !matches!(bytes[i], b',' | b'}') {
        i += 1;
    }
    Some(String::from(json[pos..i].trim()))
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let raw = extract_json_raw_value(json, key)?;
    raw.parse::<u64>().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let raw = extract_json_raw_value(json, key)?;
    match raw.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn unescape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}
