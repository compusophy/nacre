//! utf-8 safe lexer, depth-guarded s-expression parser, and canonical printer.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arena::{Arena, Node, TermId};
use crate::diag::{Diag, DiagCode, Span};

pub const MAX_PARSE_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokKind {
    LParen,
    RParen,
    Hole,
    Int(i64),
    Str(Vec<u8>),
    Var(String),
    Sym(String),
}

struct Token {
    kind: TokKind,
    span: Span,
}

fn lex(src: &str) -> Result<Vec<Token>, Diag> {
    let bytes = src.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];
        // whitespace
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
            continue;
        }
        // line comment
        if b == b';' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'(' {
            out.push(Token {
                kind: TokKind::LParen,
                span: Span::new(i, i + 1),
            });
            i += 1;
            continue;
        }
        if b == b')' {
            out.push(Token {
                kind: TokKind::RParen,
                span: Span::new(i, i + 1),
            });
            i += 1;
            continue;
        }
        if b == b'"' {
            let start = i;
            i += 1;
            let mut buf = Vec::new();
            let mut closed = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'"' {
                    i += 1;
                    closed = true;
                    break;
                }
                if c == b'\\' {
                    i += 1;
                    if i >= bytes.len() {
                        break;
                    }
                    let esc = match bytes[i] {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'\\' => b'\\',
                        b'"' => b'"',
                        other => {
                            return Err(Diag::new(
                                DiagCode::UnexpectedChar,
                                Span::new(i - 1, i + 1),
                                format!("invalid escape sequence \\{}", other as char),
                            ));
                        }
                    };
                    buf.push(esc);
                    i += 1;
                } else {
                    buf.push(c);
                    i += 1;
                }
            }
            if !closed {
                return Err(Diag::new(
                    DiagCode::UnclosedString,
                    Span::new(start, i),
                    "unclosed string literal",
                ));
            }
            out.push(Token {
                kind: TokKind::Str(buf),
                span: Span::new(start, i),
            });
            continue;
        }

        // atom: int, var (?name), hole (_), or symbol
        if is_atom_byte(b) {
            let start = i;
            while i < bytes.len() && is_atom_byte(bytes[i]) {
                i += 1;
            }
            let text = &src[start..i];
            let span = Span::new(start, i);

            if text == "_" {
                out.push(Token {
                    kind: TokKind::Hole,
                    span,
                });
            } else if let Some(rest) = text.strip_prefix('?') {
                if rest.is_empty() {
                    return Err(Diag::new(
                        DiagCode::UnexpectedChar,
                        span,
                        "empty variable name after '?'",
                    ));
                }
                out.push(Token {
                    kind: TokKind::Var(String::from(rest)),
                    span,
                });
            } else if is_int_token(text) {
                match text.parse::<i64>() {
                    Ok(v) => out.push(Token {
                        kind: TokKind::Int(v),
                        span,
                    }),
                    Err(_) => {
                        return Err(Diag::new(
                            DiagCode::InvalidInt,
                            span,
                            format!("integer out of i64 range: {}", text),
                        ));
                    }
                }
            } else {
                out.push(Token {
                    kind: TokKind::Sym(String::from(text)),
                    span,
                });
            }
            continue;
        }

        return Err(Diag::new(
            DiagCode::UnexpectedChar,
            Span::new(i, i + 1),
            format!("unexpected byte 0x{:02x}", b),
        ));
    }

    Ok(out)
}

fn is_atom_byte(b: u8) -> bool {
    !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'"' | b';') && b >= 0x21 && b <= 0x7e
}

fn is_int_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let start = if bytes[0] == b'-' {
        if bytes.len() == 1 {
            return false;
        }
        1
    } else {
        0
    };
    bytes[start..].iter().all(|b| b.is_ascii_digit())
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn parse_term(&mut self, arena: &mut Arena, depth: usize) -> Result<TermId, Diag> {
        if depth > MAX_PARSE_DEPTH {
            let span = self
                .tokens
                .get(self.pos)
                .map(|t| t.span)
                .unwrap_or(Span::SYNTHETIC);
            return Err(Diag::new(
                DiagCode::MaxParseDepth,
                span,
                "maximum nesting depth exceeded",
            ));
        }

        let tok = self.tokens.get(self.pos).ok_or_else(|| {
            Diag::new(DiagCode::UnexpectedEof, Span::SYNTHETIC, "unexpected end of input")
        })?;
        self.pos += 1;

        match &tok.kind {
            TokKind::Hole => Ok(arena.term_hole()),
            TokKind::Int(v) => Ok(arena.mk_int(*v)?.0),
            TokKind::Str(bs) => Ok(arena.mk_bytes(bs)?.0),
            TokKind::Var(name) => {
                let sym = arena.intern_sym(name);
                Ok(arena.mk_var(sym)?.0)
            }
            TokKind::Sym(name) => {
                let sym = arena.intern_sym(name);
                Ok(arena.mk_sym(sym)?.0)
            }
            TokKind::RParen => Err(Diag::new(
                DiagCode::UnexpectedChar,
                tok.span,
                "unexpected ')'",
            )),
            TokKind::LParen => {
                let open_span = tok.span;
                // empty () -> nil
                if let Some(next) = self.tokens.get(self.pos) {
                    if matches!(next.kind, TokKind::RParen) {
                        self.pos += 1;
                        return Ok(arena.term_nil());
                    }
                }
                let head_tok = self.tokens.get(self.pos).ok_or_else(|| {
                    Diag::new(DiagCode::UnclosedParen, open_span, "unclosed '('")
                })?;
                let head_sym = match &head_tok.kind {
                    TokKind::Sym(name) => {
                        self.pos += 1;
                        arena.intern_sym(name)
                    }
                    _ => {
                        return Err(Diag::new(
                            DiagCode::UnexpectedChar,
                            head_tok.span,
                            "application head must be a symbol",
                        ));
                    }
                };
                let mut args = Vec::new();
                loop {
                    let next = self.tokens.get(self.pos).ok_or_else(|| {
                        Diag::new(DiagCode::UnclosedParen, open_span, "unclosed '('")
                    })?;
                    if matches!(next.kind, TokKind::RParen) {
                        self.pos += 1;
                        break;
                    }
                    let arg = self.parse_term(arena, depth + 1)?;
                    args.push(arg);
                }
                Ok(arena.mk_app(head_sym, &args)?.0)
            }
        }
    }
}

/// parse a single term from source text.
pub fn parse_term(arena: &mut Arena, src: &str) -> Result<TermId, Diag> {
    let tokens = lex(src)?;
    if tokens.is_empty() {
        return Err(Diag::new(
            DiagCode::UnexpectedEof,
            Span::SYNTHETIC,
            "empty input",
        ));
    }
    let mut p = Parser { tokens: &tokens, pos: 0 };
    let term = p.parse_term(arena, 0)?;
    if p.pos < tokens.len() {
        return Err(Diag::new(
            DiagCode::TrailingTokens,
            tokens[p.pos].span,
            "unexpected trailing tokens",
        ));
    }
    Ok(term)
}

/// parse a sequence of top-level terms (e.g. a module of `(rule ...)` definitions).
pub fn parse_terms(arena: &mut Arena, src: &str) -> Result<Vec<TermId>, Diag> {
    let tokens = lex(src)?;
    let mut p = Parser { tokens: &tokens, pos: 0 };
    let mut terms = Vec::new();
    while p.pos < tokens.len() {
        terms.push(p.parse_term(arena, 0)?);
    }
    Ok(terms)
}

/// render any term in canonical s-expression form (round-trip safe).
pub fn print_term(arena: &Arena, id: TermId) -> String {
    let mut out = String::new();
    write_term(arena, id, &mut out);
    out
}

fn write_term(arena: &Arena, id: TermId, out: &mut String) {
    match arena.node(id) {
        Node::Int(v) => {
            out.push_str(&format!("{}", v));
        }
        Node::Bytes(bs) => {
            out.push('"');
            if let Ok(s) = core::str::from_utf8(bs) {
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
            } else {
                for &b in bs.iter() {
                    out.push_str(&format!("{:02x}", b));
                }
            }
            out.push('"');
        }
        Node::Sym(s) => {
            out.push_str(arena.sym_name(*s));
        }
        Node::Var(s) => {
            out.push('?');
            out.push_str(arena.sym_name(*s));
        }
        Node::Hole => {
            out.push('_');
        }
        Node::App(head, args) => {
            out.push('(');
            out.push_str(arena.sym_name(*head));
            for &a in args.iter() {
                out.push(' ');
                write_term(arena, a, out);
            }
            out.push(')');
        }
    }
}
