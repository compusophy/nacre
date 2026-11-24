//! coded, spanned diagnostics that never panic (utf-8 boundary safe, strictly lowercase).

use alloc::format;
use alloc::string::String;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub const SYNTHETIC: Self = Self { start: 0, end: 0 };

    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start: start.min(u32::MAX as usize) as u32,
            end: end.min(u32::MAX as usize) as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagCode {
    // lex & parse
    UnexpectedChar,
    UnclosedParen,
    UnclosedString,
    MaxParseDepth,
    InvalidInt,
    TrailingTokens,
    UnexpectedEof,
    InvalidPattern,
    // lexicon & static checks
    DuplicatePatternVar,
    UnboundVar,
    InvalidRuleForm,
    // runtime evaluation
    DivisionByZero,
    IntOverflow,
    TypeMismatch,
    ArityMismatch,
    MaxEvalDepth,
    ArenaCapExceeded,
    InvalidResume,
    InvalidFuelRequest,
    NonExhaustiveMatch,
    // journal & crystallization
    JournalHashMismatch,
    ReplayDivergence,
    MissingJournalEffect,
    NoImprovement,
    CapabilityEscalation,
    EmptyTraceSet,
}

impl DiagCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedChar => "e001",
            Self::UnclosedParen => "e002",
            Self::UnclosedString => "e003",
            Self::MaxParseDepth => "e004",
            Self::InvalidInt => "e005",
            Self::TrailingTokens => "e006",
            Self::UnexpectedEof => "e007",
            Self::InvalidPattern => "e008",
            Self::DuplicatePatternVar => "e010",
            Self::UnboundVar => "e011",
            Self::InvalidRuleForm => "e012",
            Self::DivisionByZero => "e020",
            Self::IntOverflow => "e021",
            Self::TypeMismatch => "e022",
            Self::ArityMismatch => "e023",
            Self::MaxEvalDepth => "e024",
            Self::ArenaCapExceeded => "e025",
            Self::InvalidResume => "e026",
            Self::InvalidFuelRequest => "e027",
            Self::NonExhaustiveMatch => "e028",
            Self::JournalHashMismatch => "e030",
            Self::ReplayDivergence => "e031",
            Self::MissingJournalEffect => "e032",
            Self::NoImprovement => "e033",
            Self::CapabilityEscalation => "e034",
            Self::EmptyTraceSet => "e035",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diag {
    pub code: DiagCode,
    pub span: Span,
    pub message: String,
}

impl Diag {
    pub fn new(code: DiagCode, span: Span, message: impl Into<String>) -> Self {
        let raw = message.into();
        Self {
            code,
            span,
            message: raw.to_ascii_lowercase(),
        }
    }

    pub fn runtime(code: DiagCode, message: impl Into<String>) -> Self {
        Self::new(code, Span::SYNTHETIC, message)
    }

    /// render a utf-8 safe caret snippet for human/model consumption (all lowercase).
    pub fn render_with_source(&self, src: &str) -> String {
        if src.is_empty() || (self.span.start == 0 && self.span.end == 0) {
            return format!("error[{}]: {}", self.code.as_str(), self.message);
        }
        let start = floor_char_boundary(src, (self.span.start as usize).min(src.len()));
        let end = floor_char_boundary(src, (self.span.end as usize).min(src.len()).max(start));
        let line_start = src[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = src[start..].find('\n').map(|i| start + i).unwrap_or(src.len());
        let line_num = src[..line_start].bytes().filter(|&b| b == b'\n').count() + 1;
        let col = src[line_start..start].chars().count() + 1;
        let caret_len = src[start..end].chars().count().max(1);
        let line_text = &src[line_start..line_end];

        let mut spaces = String::new();
        for _ in 0..(col - 1) {
            spaces.push(' ');
        }
        let mut carets = String::new();
        for _ in 0..caret_len {
            carets.push('^');
        }
        format!(
            "error[{}]: {} (line {}, col {})\n  | {}\n  | {}{}",
            self.code.as_str(),
            self.message,
            line_num,
            col,
            line_text,
            spaces,
            carets
        )
    }
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}]: {}", self.code.as_str(), self.message)
    }
}
