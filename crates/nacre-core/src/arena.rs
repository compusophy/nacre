//! hash-consed merkle-dag term arena with pre-interned builtins and hard memory cap.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::diag::{Diag, DiagCode};
use crate::hash::{Hash256, Sha256, TAG_APP, TAG_BYTES, TAG_HOLE, TAG_INT, TAG_SYM, TAG_VAR};

pub const DEFAULT_MAX_NODES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TermId(pub u32);

/// pre-interned symbol constants for o(1) dispatch without string comparisons.
pub mod sym {
    use super::SymId;

    // special forms & core tags
    pub const QUOTE: SymId = SymId(0);
    pub const IF: SymId = SymId(1);
    pub const MATCH: SymId = SymId(2);
    pub const CASE: SymId = SymId(3);
    pub const PERFORM: SymId = SymId(4);
    pub const HANDLE: SymId = SymId(5);
    pub const RESUME: SymId = SymId(6);
    pub const CONT: SymId = SymId(7);
    pub const RULE: SymId = SymId(8);
    pub const EVAL: SymId = SymId(9);

    // literals & standard result constructors
    pub const TRUE: SymId = SymId(10);
    pub const FALSE: SymId = SymId(11);
    pub const NIL: SymId = SymId(12);
    pub const CONS: SymId = SymId(13);
    pub const LIST: SymId = SymId(14);
    pub const OK: SymId = SymId(15);
    pub const ERR: SymId = SymId(16);
    pub const FAULT: SymId = SymId(17);
    pub const EXHAUSTED: SymId = SymId(18);

    // arithmetic & comparisons
    pub const ADD: SymId = SymId(19);
    pub const SUB: SymId = SymId(20);
    pub const MUL: SymId = SymId(21);
    pub const DIV: SymId = SymId(22);
    pub const MOD: SymId = SymId(23);
    pub const NEG: SymId = SymId(24);
    pub const EQ: SymId = SymId(25);
    pub const LT: SymId = SymId(26);
    pub const LE: SymId = SymId(27);
    pub const GT: SymId = SymId(28);
    pub const GE: SymId = SymId(29);
    pub const NOT: SymId = SymId(30);
    pub const AND: SymId = SymId(31);
    pub const OR: SymId = SymId(32);

    // string / bytes builtins
    pub const STR_LEN: SymId = SymId(33);
    pub const STR_CAT: SymId = SymId(34);
    pub const STR_SLICE: SymId = SymId(35);
    pub const STR_CONTAINS: SymId = SymId(36);
    pub const STR_STARTS_WITH: SymId = SymId(37);
    pub const INT_TO_STR: SymId = SymId(38);
    pub const STR_TO_INT: SymId = SymId(39);

    // homoiconic term reflection builtins
    pub const TERM_HASH: SymId = SymId(40);
    pub const TERM_TAG: SymId = SymId(41);
    pub const TERM_ARITY: SymId = SymId(42);
    pub const TERM_ARG: SymId = SymId(43);
    pub const TERM_MAKE: SymId = SymId(44);

    pub const PREINTERNED: &[&str] = &[
        "quote",
        "if",
        "match",
        "case",
        "perform",
        "handle",
        "resume",
        "cont",
        "rule",
        "eval",
        "true",
        "false",
        "nil",
        "cons",
        "list",
        "ok",
        "err",
        "fault",
        "exhausted",
        "add",
        "sub",
        "mul",
        "div",
        "mod",
        "neg",
        "eq",
        "lt",
        "le",
        "gt",
        "ge",
        "not",
        "and",
        "or",
        "str_len",
        "str_cat",
        "str_slice",
        "str_contains",
        "str_starts_with",
        "int_to_str",
        "str_to_int",
        "term_hash",
        "term_tag",
        "term_arity",
        "term_arg",
        "term_make",
    ];

    pub fn is_reserved_head(id: SymId) -> bool {
        id.0 <= TERM_MAKE.0
            && !matches!(id, OK | ERR | FAULT | EXHAUSTED | CONS | NIL | TRUE | FALSE)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Int(i64),
    Bytes(Box<[u8]>),
    Sym(SymId),
    Var(SymId),
    Hole,
    App(SymId, Box<[TermId]>),
}

struct NodeEntry {
    node: Node,
    hash: Hash256,
}

/// hash-consed merkle-dag arena. identical terms share the exact same `TermId` and `Hash256`.
pub struct Arena {
    sym_names: Vec<String>,
    sym_index: BTreeMap<String, SymId>,
    nodes: Vec<NodeEntry>,
    hash_index: BTreeMap<Hash256, TermId>,
    max_nodes: usize,
    // cached singleton term ids for common constants
    t_hole: TermId,
    t_true: TermId,
    t_false: TermId,
    t_nil: TermId,
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

impl Arena {
    pub fn new() -> Self {
        Self::with_capacity_limit(DEFAULT_MAX_NODES)
    }

    pub fn with_capacity_limit(max_nodes: usize) -> Self {
        let mut arena = Self {
            sym_names: Vec::with_capacity(64),
            sym_index: BTreeMap::new(),
            nodes: Vec::with_capacity(256),
            hash_index: BTreeMap::new(),
            max_nodes: max_nodes.max(16),
            t_hole: TermId(0),
            t_true: TermId(0),
            t_false: TermId(0),
            t_nil: TermId(0),
        };
        for &name in sym::PREINTERNED {
            arena.intern_sym(name);
        }
        arena.t_hole = arena.intern_unchecked(Node::Hole);
        arena.t_true = arena.intern_unchecked(Node::Sym(sym::TRUE));
        arena.t_false = arena.intern_unchecked(Node::Sym(sym::FALSE));
        arena.t_nil = arena.intern_unchecked(Node::Sym(sym::NIL));
        arena
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn term_hole(&self) -> TermId {
        self.t_hole
    }

    pub fn term_true(&self) -> TermId {
        self.t_true
    }

    pub fn term_false(&self) -> TermId {
        self.t_false
    }

    pub fn term_bool(&self, b: bool) -> TermId {
        if b {
            self.t_true
        } else {
            self.t_false
        }
    }

    pub fn term_nil(&self) -> TermId {
        self.t_nil
    }

    pub fn intern_sym(&mut self, name: &str) -> SymId {
        if let Some(&id) = self.sym_index.get(name) {
            return id;
        }
        let id = SymId(self.sym_names.len() as u32);
        let owned = String::from(name);
        self.sym_names.push(owned.clone());
        self.sym_index.insert(owned, id);
        id
    }

    pub fn sym_name(&self, id: SymId) -> &str {
        self.sym_names
            .get(id.0 as usize)
            .map(|s| s.as_str())
            .unwrap_or("<unknown>")
    }

    pub fn lookup_sym(&self, name: &str) -> Option<SymId> {
        self.sym_index.get(name).copied()
    }

    pub fn node(&self, id: TermId) -> &Node {
        &self.nodes[id.0 as usize].node
    }

    pub fn hash(&self, id: TermId) -> Hash256 {
        self.nodes[id.0 as usize].hash
    }

    fn compute_hash(&self, node: &Node) -> Hash256 {
        let mut h = Sha256::new();
        match node {
            Node::Int(v) => {
                h.update_u8(TAG_INT);
                h.update_i64(*v);
            }
            Node::Bytes(bs) => {
                h.update_u8(TAG_BYTES);
                h.update_len_bytes(bs);
            }
            Node::Sym(s) => {
                h.update_u8(TAG_SYM);
                h.update_len_bytes(self.sym_name(*s).as_bytes());
            }
            Node::Var(s) => {
                h.update_u8(TAG_VAR);
                h.update_len_bytes(self.sym_name(*s).as_bytes());
            }
            Node::Hole => {
                h.update_u8(TAG_HOLE);
            }
            Node::App(head, args) => {
                h.update_u8(TAG_APP);
                h.update_len_bytes(self.sym_name(*head).as_bytes());
                h.update_u32(args.len() as u32);
                for &arg in args.iter() {
                    h.update_hash(&self.hash(arg));
                }
            }
        }
        h.finalize()
    }

    fn intern_unchecked(&mut self, node: Node) -> TermId {
        let hash = self.compute_hash(&node);
        if let Some(&existing) = self.hash_index.get(&hash) {
            return existing;
        }
        let id = TermId(self.nodes.len() as u32);
        self.nodes.push(NodeEntry { node, hash });
        self.hash_index.insert(hash, id);
        id
    }

    /// intern a node, returning `(TermId, allocated_new)` so fuel can charge 1 for new nodes and 0 for shared hits.
    pub fn intern(&mut self, node: Node) -> Result<(TermId, bool), Diag> {
        let hash = self.compute_hash(&node);
        if let Some(&existing) = self.hash_index.get(&hash) {
            return Ok((existing, false));
        }
        if self.nodes.len() >= self.max_nodes {
            return Err(Diag::runtime(
                DiagCode::ArenaCapExceeded,
                "arena node cap exceeded",
            ));
        }
        let id = TermId(self.nodes.len() as u32);
        self.nodes.push(NodeEntry { node, hash });
        self.hash_index.insert(hash, id);
        Ok((id, true))
    }

    pub fn mk_int(&mut self, v: i64) -> Result<(TermId, bool), Diag> {
        self.intern(Node::Int(v))
    }

    pub fn mk_bytes(&mut self, bytes: &[u8]) -> Result<(TermId, bool), Diag> {
        self.intern(Node::Bytes(bytes.to_vec().into_boxed_slice()))
    }

    pub fn mk_str(&mut self, s: &str) -> Result<(TermId, bool), Diag> {
        self.mk_bytes(s.as_bytes())
    }

    pub fn mk_sym(&mut self, id: SymId) -> Result<(TermId, bool), Diag> {
        self.intern(Node::Sym(id))
    }

    pub fn mk_var(&mut self, id: SymId) -> Result<(TermId, bool), Diag> {
        self.intern(Node::Var(id))
    }

    pub fn mk_app(&mut self, head: SymId, args: &[TermId]) -> Result<(TermId, bool), Diag> {
        self.intern(Node::App(head, args.to_vec().into_boxed_slice()))
    }

    /// count unique merkle-dag nodes reachable from `root` (exact live footprint).
    pub fn live_node_count(&self, root: TermId) -> usize {
        let mut seen = BTreeMap::new();
        let mut stack = alloc::vec![root];
        while let Some(id) = stack.pop() {
            if seen.insert(id, ()).is_some() {
                continue;
            }
            if let Node::App(_, args) = self.node(id) {
                for &a in args.iter() {
                    stack.push(a);
                }
            }
        }
        seen.len()
    }
}
