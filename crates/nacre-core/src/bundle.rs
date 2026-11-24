//! portable `.ncrystal` verified skill bundles.
//!
//! a `.ncrystal` file packages a crystallized lexicon, its `CrystalCert` proof metadata,
//! and an optional tier-2 wasm reflex into one human-auditable, hash-sealed artifact that
//! anyone can cryptographically verify offline before running a single instruction.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::Arena;
use crate::diag::{Diag, DiagCode};
use crate::distill::CrystalCert;
use crate::hash::{sha256, Hash256, Sha256};
use crate::lexicon::Lexicon;
use crate::wasm_emit::WasmReflex;

const TAG_BUNDLE: u8 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrystalBundle {
    pub name: String,
    pub lexicon_src: String,
    pub cert: CrystalCert,
    pub wasm_entry: Option<String>,
    pub wasm_hash: Option<Hash256>,
    pub wasm_bytes: Option<Vec<u8>>,
    pub bundle_hash: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundleInfo {
    pub name: String,
    pub lexicon_hash: Hash256,
    pub rule_count: usize,
    pub static_caps: Vec<String>,
    pub is_pure: bool,
    pub effects_eliminated: u64,
    pub wasm_size: Option<usize>,
    pub bundle_hash: Hash256,
}

impl CrystalBundle {
    pub fn new(
        name: impl Into<String>,
        lexicon_src: impl Into<String>,
        cert: CrystalCert,
        wasm: Option<&WasmReflex>,
    ) -> Self {
        let mut bundle = Self {
            name: name.into().to_ascii_lowercase(),
            lexicon_src: lexicon_src.into(),
            cert,
            wasm_entry: wasm.map(|w| w.entry_name.to_ascii_lowercase()),
            wasm_hash: wasm.map(|w| w.wasm_hash),
            wasm_bytes: wasm.map(|w| w.wasm_bytes.clone()),
            bundle_hash: Hash256::ZERO,
        };
        bundle.bundle_hash = bundle.compute_hash();
        bundle
    }

    pub fn compute_hash(&self) -> Hash256 {
        let mut h = Sha256::new();
        h.update_u8(TAG_BUNDLE);
        h.update_len_bytes(self.name.as_bytes());
        h.update_len_bytes(self.lexicon_src.as_bytes());
        h.update_hash(&self.cert.cert_hash);
        h.update_hash(&self.cert.base_lexicon_hash);
        h.update_hash(&self.cert.new_lexicon_hash);
        h.update_hash(&self.cert.traces_merkle_root);
        h.update_u32(self.cert.trace_count);
        h.update_u64(self.cert.base_effects);
        h.update_u64(self.cert.new_effects);
        h.update_u64(self.cert.base_fuel);
        h.update_u64(self.cert.new_fuel);
        match (&self.wasm_entry, &self.wasm_hash, &self.wasm_bytes) {
            (Some(e), Some(wh), Some(wb)) => {
                h.update_u8(1);
                h.update_len_bytes(e.as_bytes());
                h.update_hash(wh);
                h.update_len_bytes(wb);
            }
            _ => h.update_u8(0),
        }
        h.finalize()
    }

    /// cryptographically and statically verify a `.ncrystal` bundle in a fresh arena:
    ///   1. bundle_hash seals every field against tampering
    ///   2. lexicon_src parses cleanly and hashes to `cert.new_lexicon_hash`
    ///   3. actual static capabilities of the lexicon are a subset of `cert.caps_after`
    ///   4. optional embedded wasm bytes match `wasm_hash` and start with valid `\0asm\x01`
    pub fn verify(&self) -> Result<VerifiedBundleInfo, Diag> {
        let expected_bundle = self.compute_hash();
        if expected_bundle != self.bundle_hash {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                format!(
                    "bundle hash mismatch: expected {}, got {}",
                    expected_bundle.short_hex(),
                    self.bundle_hash.short_hex()
                ),
            ));
        }

        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        lex.load_source(&mut arena, &self.lexicon_src)?;

        let actual_lex_hash = lex.hash(&arena);
        if actual_lex_hash != self.cert.new_lexicon_hash {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                format!(
                    "lexicon hash mismatch: certified {}, actual {}",
                    self.cert.new_lexicon_hash.short_hex(),
                    actual_lex_hash.short_hex()
                ),
            ));
        }

        // statically audit every rule in the lexicon to guarantee no hidden capabilities
        let mut actual_caps: BTreeSet<String> = BTreeSet::new();
        for head in lex.heads() {
            if let Some(clauses) = lex.rules_for(head) {
                for r in clauses {
                    for &c in &r.direct_caps {
                        actual_caps.insert(String::from(arena.sym_name(c)));
                    }
                }
            }
        }
        let declared_caps: BTreeSet<String> = self.cert.caps_after.iter().cloned().collect();
        for c in &actual_caps {
            if !declared_caps.contains(c) {
                return Err(Diag::runtime(
                    DiagCode::CapabilityEscalation,
                    format!("undeclared capability '{}' found in bundle lexicon", c),
                ));
            }
        }

        let wasm_size = match (&self.wasm_hash, &self.wasm_bytes) {
            (Some(wh), Some(wb)) => {
                if wb.len() < 8 || &wb[0..8] != b"\x00asm\x01\x00\x00\x00" {
                    return Err(Diag::runtime(
                        DiagCode::JournalHashMismatch,
                        "embedded wasm reflex has invalid header",
                    ));
                }
                if sha256(wb) != *wh {
                    return Err(Diag::runtime(
                        DiagCode::JournalHashMismatch,
                        "embedded wasm reflex hash mismatch",
                    ));
                }
                Some(wb.len())
            }
            (None, None) => None,
            _ => {
                return Err(Diag::runtime(
                    DiagCode::JournalHashMismatch,
                    "incomplete embedded wasm reflex metadata",
                ));
            }
        };

        let static_caps: Vec<String> = actual_caps.into_iter().collect();
        let is_pure = static_caps.is_empty();

        Ok(VerifiedBundleInfo {
            name: self.name.clone(),
            lexicon_hash: actual_lex_hash,
            rule_count: lex.rule_count(),
            static_caps,
            is_pure,
            effects_eliminated: self.cert.effects_eliminated(),
            wasm_size,
            bundle_hash: self.bundle_hash,
        })
    }

    /// encode as compact, human-auditable `.ncrystal` text format.
    pub fn encode_text(&self) -> String {
        let mut out = String::new();
        out.push_str("nacre-crystal-v1\n");
        out.push_str(&format!("name {}\n", self.name));
        out.push_str(&format!("cert_hash {}\n", self.cert.cert_hash.to_hex()));
        out.push_str(&format!("base_lex {}\n", self.cert.base_lexicon_hash.to_hex()));
        out.push_str(&format!("new_lex {}\n", self.cert.new_lexicon_hash.to_hex()));
        out.push_str(&format!("traces_root {}\n", self.cert.traces_merkle_root.to_hex()));
        out.push_str(&format!("trace_count {}\n", self.cert.trace_count));
        out.push_str(&format!("effects {} {}\n", self.cert.base_effects, self.cert.new_effects));
        out.push_str(&format!("fuel {} {}\n", self.cert.base_fuel, self.cert.new_fuel));
        out.push_str(&format!("caps_before {}\n", self.cert.caps_before.join(",")));
        out.push_str(&format!("caps_after {}\n", self.cert.caps_after.join(",")));
        if let (Some(entry), Some(wh), Some(wb)) =
            (&self.wasm_entry, &self.wasm_hash, &self.wasm_bytes)
        {
            out.push_str(&format!("wasm_entry {}\n", entry));
            out.push_str(&format!("wasm_hash {}\n", wh.to_hex()));
            out.push_str(&format!("wasm_hex {}\n", bytes_to_hex(wb)));
        }
        out.push_str("lexicon_begin\n");
        out.push_str(&self.lexicon_src);
        if !self.lexicon_src.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("lexicon_end\n");
        out.push_str(&format!("bundle_hash {}\n", self.bundle_hash.to_hex()));
        out
    }

    pub fn decode_text(input: &str) -> Result<Self, Diag> {
        let lines: Vec<&str> = input.lines().collect();
        let mut idx = 0usize;
        let next = |idx: &mut usize| -> Result<&str, Diag> {
            let l = lines
                .get(*idx)
                .copied()
                .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "truncated .ncrystal"))?;
            *idx += 1;
            Ok(l)
        };

        if next(&mut idx)? != "nacre-crystal-v1" {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                "unsupported .ncrystal header",
            ));
        }

        let name = strip_prefix(next(&mut idx)?, "name ")?;
        let cert_hash = parse_hex(next(&mut idx)?, "cert_hash ")?;
        let base_lexicon_hash = parse_hex(next(&mut idx)?, "base_lex ")?;
        let new_lexicon_hash = parse_hex(next(&mut idx)?, "new_lex ")?;
        let traces_merkle_root = parse_hex(next(&mut idx)?, "traces_root ")?;
        let trace_count = parse_u64(next(&mut idx)?, "trace_count ")? as u32;
        let (base_effects, new_effects) = parse_u64_pair(next(&mut idx)?, "effects ")?;
        let (base_fuel, new_fuel) = parse_u64_pair(next(&mut idx)?, "fuel ")?;
        let caps_before = parse_csv(next(&mut idx)?, "caps_before ")?;
        let caps_after = parse_csv(next(&mut idx)?, "caps_after ")?;

        let mut wasm_entry = None;
        let mut wasm_hash = None;
        let mut wasm_bytes = None;

        let mut line = next(&mut idx)?;
        if let Some(rest) = line.strip_prefix("wasm_entry ") {
            wasm_entry = Some(String::from(rest.trim()));
            wasm_hash = Some(parse_hex(next(&mut idx)?, "wasm_hash ")?);
            let hex = strip_prefix(next(&mut idx)?, "wasm_hex ")?;
            wasm_bytes = Some(hex_to_bytes(hex.trim())?);
            line = next(&mut idx)?;
        }

        if line != "lexicon_begin" {
            return Err(Diag::runtime(
                DiagCode::JournalHashMismatch,
                "expected lexicon_begin marker",
            ));
        }
        let mut lex_lines = Vec::new();
        loop {
            let l = next(&mut idx)?;
            if l == "lexicon_end" {
                break;
            }
            lex_lines.push(l);
        }
        let lexicon_src = lex_lines.join("\n");
        let bundle_hash = parse_hex(next(&mut idx)?, "bundle_hash ")?;

        let cert = CrystalCert {
            base_lexicon_hash,
            new_lexicon_hash,
            traces_merkle_root,
            trace_count,
            base_effects,
            new_effects,
            base_fuel,
            new_fuel,
            caps_before,
            caps_after,
            cert_hash,
        };

        let bundle = Self {
            name,
            lexicon_src,
            cert,
            wasm_entry,
            wasm_hash,
            wasm_bytes,
            bundle_hash,
        };
        bundle.verify()?;
        Ok(bundle)
    }
}

fn strip_prefix(line: &str, pfx: &str) -> Result<String, Diag> {
    line.strip_prefix(pfx)
        .map(String::from)
        .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, format!("expected '{}'", pfx.trim())))
}

fn parse_hex(line: &str, pfx: &str) -> Result<Hash256, Diag> {
    let raw = strip_prefix(line, pfx)?;
    Hash256::from_hex(raw.trim())
        .ok_or_else(|| Diag::runtime(DiagCode::JournalHashMismatch, "invalid hex hash in bundle"))
}

fn parse_u64(line: &str, pfx: &str) -> Result<u64, Diag> {
    let raw = strip_prefix(line, pfx)?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "invalid integer in bundle"))
}

fn parse_u64_pair(line: &str, pfx: &str) -> Result<(u64, u64), Diag> {
    let raw = strip_prefix(line, pfx)?;
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(Diag::runtime(DiagCode::JournalHashMismatch, "expected pair of integers"));
    }
    let a = parts[0]
        .parse::<u64>()
        .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "bad integer"))?;
    let b = parts[1]
        .parse::<u64>()
        .map_err(|_| Diag::runtime(DiagCode::JournalHashMismatch, "bad integer"))?;
    Ok((a, b))
}

fn parse_csv(line: &str, pfx: &str) -> Result<Vec<String>, Diag> {
    let raw = line.strip_prefix(pfx).unwrap_or_else(|| {
        if line == pfx.trim() {
            ""
        } else {
            ""
        }
    });
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(raw
        .split(',')
        .map(|s| String::from(s.trim()))
        .filter(|s| !s.is_empty())
        .collect())
}

fn bytes_to_hex(bs: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bs.len() * 2);
    for &b in bs {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, Diag> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(Diag::runtime(DiagCode::JournalHashMismatch, "odd-length hex string"));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = nib(b[i])?;
        let lo = nib(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nib(c: u8) -> Result<u8, Diag> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Diag::runtime(DiagCode::JournalHashMismatch, "invalid hex digit")),
    }
}
