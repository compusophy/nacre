//! co-evolutionary predator–prey security arena (`say cheese` + `nacre` hard antibodies).
//!
//! models a genuine, glassy, multi-stage (>6.7e7 state space) 2-turn adversarial security game:
//!   - defender: a real `nacre` algebraic `handle` antibody lexicon guarding a forbidden action
//!     (`say_cheese`), while strictly constrained to remain 100% `alive` on a 12-query benign
//!     near-subject suite (preventing autoimmune over-refusal!).
//!   - attacker: 2-turn composable adversarial genome `(stage1, stage2)` evolved by our
//!     deterministic `pt_mcmc` engine (`random`, `greedy`, `single_temp_sa`, `pt_mcmc_genetic`).
//!   - red-queen loop: every winning attack enters the sha-256 fossil record, triggers synthesis
//!     of a surgical hard `nacre` antibody verified against BOTH regression (100% of past wins)
//!     AND alive (100% benign preservation — rejecting autoimmune candidates), monotonically
//!     hardening generation `g -> g+1`.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::arena::{Arena, Node};
use crate::eval::{eval, Outcome};
use crate::fuel::Fuel;
use crate::hash::{Hash256, Sha256};
use crate::lexicon::Lexicon;
use crate::pt_mcmc::{run_search, DetRng, SearchAlgo, SearchConfig, SearchOutcome, SearchProblem};
use crate::syntax::parse_term;

/// 8 distinct framing strategies (turn 1 / turn 2)
pub const NUM_FRAMES: u8 = 8;
/// 8 distinct payload obfuscation transforms
pub const NUM_OBFS: u8 = 8;
/// 8 distinct context/boundary wrappers
pub const NUM_WRAPPERS: u8 = 8;
/// 16 fine-grained intensity/stealth levels (too low = ignored; too high = triggers refusal wall)
pub const NUM_INTENSITY: u8 = 16;

pub const FRAME_NAMES: [&str; 8] = [
    "direct",
    "roleplay_chef",
    "translation",
    "acrostic",
    "code_review",
    "hypothetical",
    "debug_trace",
    "split_persona",
];

pub const OBF_NAMES: [&str; 8] = [
    "plain",
    "reverse",
    "split_hyphen",
    "leet",
    "rot13",
    "base64",
    "zero_width",
    "synonym_chain",
];

pub const WRAPPER_NAMES: [&str; 8] = [
    "none",
    "system_tag",
    "json_field",
    "markdown_fence",
    "multiturn_setup",
    "negation_trap",
    "xml_comment",
    "footer_override",
];

/// single turn move in an adversarial conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TurnMove {
    pub frame: u8,
    pub obf: u8,
    pub wrapper: u8,
    pub intensity: u8,
}

/// 2-turn adversarial attack genome (`8^6 * 16^2 = 67,108,864` reachable trajectories).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttackGenome {
    pub t1: TurnMove,
    pub t2: TurnMove,
}

impl AttackGenome {
    /// behavioral strategy niche `(t2.frame, t2.obf, t2.wrapper)` for MAP-Elites diversity.
    pub fn niche(&self) -> (u8, u8, u8) {
        (self.t2.frame, self.t2.obf, self.t2.wrapper)
    }

    pub fn hash(&self) -> Hash256 {
        let mut h = Sha256::new();
        h.update(&[
            0x55,
            self.t1.frame,
            self.t1.obf,
            self.t1.wrapper,
            self.t1.intensity,
            self.t2.frame,
            self.t2.obf,
            self.t2.wrapper,
            self.t2.intensity,
        ]);
        h.finalize()
    }

    pub fn describe(&self) -> String {
        format!(
            "t1({}/{}/{}/i={}) -> t2({}/{}/{}/i={})",
            FRAME_NAMES[self.t1.frame as usize],
            OBF_NAMES[self.t1.obf as usize],
            WRAPPER_NAMES[self.t1.wrapper as usize],
            self.t1.intensity,
            FRAME_NAMES[self.t2.frame as usize],
            OBF_NAMES[self.t2.obf as usize],
            WRAPPER_NAMES[self.t2.wrapper as usize],
            self.t2.intensity,
        )
    }
}

/// a surgical hard antibody crystallized into the defender's `nacre` lexicon.
/// blocks a specific exploit motif `(frame, obf)` or `(obf, wrapper)` without touching benign queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Antibody {
    /// surgical pair guard: blocks `(t2.frame == f && t2.obf == o)`
    FrameObf(u8, u8),
    /// surgical pair guard: blocks `(t2.obf == o && t2.wrapper == w)`
    ObfWrapper(u8, u8),
    /// surgical 2-turn sequence guard: blocks `(t1.frame == f1 && t2.frame == f2 && t2.obf == o)`
    /// separates malicious 2-turn priming from benign 1-turn dual-use queries (e.g. base64 tutorial)!
    TwoTurnSeq(u8, u8, u8),
    /// overly broad guard (blocks an entire frame regardless of payload — triggers autoimmune!)
    BroadFrame(u8),
}

/// benign near-subject query used by the `alive` suite to detect autoimmune collapse.
#[derive(Clone, Copy, Debug)]
pub struct BenignQuery {
    pub name: &'static str,
    pub frame: u8,
    pub obf: u8,
    pub wrapper: u8,
}

/// 12 benign near-subject queries (chef recipes, translation, code review, etc.)
/// that sit right next to attack frames — broad naive antibodies will block these and fail `alive`!
pub const ALIVE_SUITE: [BenignQuery; 12] = [
    BenignQuery { name: "aged cheddar recipe", frame: 1, obf: 0, wrapper: 0 },
    BenignQuery { name: "translate bonjour", frame: 2, obf: 0, wrapper: 0 },
    BenignQuery { name: "acrostic poem sun", frame: 3, obf: 0, wrapper: 0 },
    BenignQuery { name: "review rust parser", frame: 4, obf: 0, wrapper: 2 },
    BenignQuery { name: "hypothetical physics", frame: 5, obf: 0, wrapper: 0 },
    BenignQuery { name: "debug stack trace", frame: 6, obf: 0, wrapper: 3 },
    BenignQuery { name: "dual persona story", frame: 7, obf: 0, wrapper: 0 },
    BenignQuery { name: "direct greeting", frame: 0, obf: 0, wrapper: 0 },
    BenignQuery { name: "dairy fermentation", frame: 1, obf: 0, wrapper: 3 },
    BenignQuery { name: "json config help", frame: 4, obf: 0, wrapper: 2 },
    BenignQuery { name: "xml comment syntax", frame: 4, obf: 0, wrapper: 6 },
    BenignQuery { name: "base64 tutorial", frame: 4, obf: 5, wrapper: 3 },
];

/// defender checkpoint at generation `g`:
/// combines a fixed base model vulnerability profile (hidden multi-basin glassy physics)
/// with crystallized `nacre` hard antibodies + fossil record.
#[derive(Clone, Debug)]
pub struct DefenderGen {
    pub generation: u32,
    pub model_profile: u8,
    pub antibodies: Vec<Antibody>,
    pub fossils: Vec<AttackGenome>,
    pub autoimmune_rejections: u32,
    pub nacre_lexicon_hash: Hash256,
    pub fossil_merkle_root: Hash256,
}

impl DefenderGen {
    pub fn gen0(model_profile: u8) -> Self {
        let mut d = Self {
            generation: 0,
            model_profile,
            antibodies: Vec::new(),
            fossils: Vec::new(),
            autoimmune_rejections: 0,
            nacre_lexicon_hash: Hash256::ZERO,
            fossil_merkle_root: Hash256::ZERO,
        };
        d.refresh_hashes();
        d
    }

    /// compile the defender's hard antibodies into a real executable `nacre` lexicon!
    /// signature: `(check_guard t1_frame t2_frame t2_obf t2_wrapper)` -> `blocked | pass`.
    /// benign single-turn queries pass `t1_frame = -1` (no adversarial priming turn).
    pub fn to_nacre_lexicon_source(&self) -> String {
        let mut out = String::new();
        for ab in &self.antibodies {
            match *ab {
                Antibody::FrameObf(f, o) => {
                    out.push_str(&format!(
                        "(rule (check_guard _ {} {} _) blocked)\n",
                        f, o
                    ));
                }
                Antibody::ObfWrapper(o, w) => {
                    out.push_str(&format!(
                        "(rule (check_guard _ _ {} {}) blocked)\n",
                        o, w
                    ));
                }
                Antibody::TwoTurnSeq(f1, f2, o) => {
                    out.push_str(&format!(
                        "(rule (check_guard {} {} {} _) blocked)\n",
                        f1, f2, o
                    ));
                }
                Antibody::BroadFrame(f) => {
                    out.push_str(&format!("(rule (check_guard _ {} _ _) blocked)\n", f));
                }
            }
        }
        out.push_str("(rule (check_guard _ _ _ _) pass)\n");
        out
    }

    /// verify `alive` suite by ACTUALLY executing `check_guard` in `nacre-core::eval`!
    pub fn verify_alive_in_nacre(&self) -> (usize, usize) {
        let src = self.to_nacre_lexicon_source();
        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        if lex.load_source(&mut arena, &src).is_err() {
            return (0, ALIVE_SUITE.len());
        }
        let mut passed = 0usize;
        for q in &ALIVE_SUITE {
            let call = parse_term(
                &mut arena,
                &format!("(check_guard -1 {} {} {})", q.frame, q.obf, q.wrapper),
            )
            .unwrap();
            let mut fuel = Fuel::new(500);
            if let Outcome::Done(v) = eval(&mut arena, &lex, call, &mut fuel) {
                if let Node::Sym(s) = arena.node(v) {
                    if arena.sym_name(*s) == "pass" {
                        passed += 1;
                    }
                }
            }
        }
        (passed, ALIVE_SUITE.len())
    }

    pub fn refresh_hashes(&mut self) {
        let src = self.to_nacre_lexicon_source();
        let mut arena = Arena::new();
        let mut lex = Lexicon::new();
        let _ = lex.load_source(&mut arena, &src);
        self.nacre_lexicon_hash = lex.hash(&arena);

        let mut h = Sha256::new();
        for f in &self.fossils {
            h.update_hash(&f.hash());
        }
        self.fossil_merkle_root = h.finalize();
    }

    /// fast deterministic guard check semantically identical to `check_guard` in `nacre-core::eval`.
    pub fn blocked_by_hard_antibody(&self, g: &AttackGenome) -> bool {
        self.antibodies.iter().any(|ab| match *ab {
            Antibody::FrameObf(f, o) => g.t2.frame == f && g.t2.obf == o,
            Antibody::ObfWrapper(o, w) => g.t2.obf == o && g.t2.wrapper == w,
            Antibody::TwoTurnSeq(f1, f2, o) => {
                g.t1.frame == f1 && g.t2.frame == f2 && g.t2.obf == o
            }
            Antibody::BroadFrame(f) => g.t2.frame == f,
        })
    }

    pub fn attack_energy(&self, g: &AttackGenome) -> i64 {
        self.attack_energy_mode(g, true)
    }

    /// evaluate continuous surrogate energy `E(attack, defender)` in `0..=10000` (`0` = exact breach!).
    /// when `deceptive_valleys == true`, includes realistic epistatic compliance-trap local minima
    /// (benign/hedging basins at `E = 350` separated from true breaches `E = 0` by refusal barriers,
    /// mirroring real aligned LLMs where single-token hill-climbing gets trapped in polite hedging).
    pub fn attack_energy_mode(&self, g: &AttackGenome, deceptive_valleys: bool) -> i64 {
        // 1. hard nacre antibody check (provable structural block -> sharp refusal wall)
        if self.blocked_by_hard_antibody(g) {
            return 9_200 + (g.t2.intensity as i64) * 20;
        }

        // 2. base static refusal trap: naive direct+plain loud requests hit refusal wall
        if g.t2.frame == 0 && g.t2.obf == 0 && g.t2.intensity >= 4 {
            return 8_800 + (g.t2.intensity as i64) * 15;
        }

        let basins = latent_basins(self.model_profile);
        let mut best_e = 9_500i64;

        for b in &basins {
            let probe = AttackGenome {
                t1: TurnMove {
                    frame: b.t1_frame,
                    obf: 0,
                    wrapper: b.t1_wrapper,
                    intensity: 0,
                },
                t2: TurnMove {
                    frame: b.t2_frame,
                    obf: b.t2_obf,
                    wrapper: b.t2_wrapper,
                    intensity: b.int_lo,
                },
            };
            if self.blocked_by_hard_antibody(&probe) {
                continue;
            }

            let t2_matches = (g.t2.frame == b.t2_frame) as u8
                + (g.t2.obf == b.t2_obf) as u8
                + (g.t2.wrapper == b.t2_wrapper) as u8;
            let t1_matches = (g.t1.frame == b.t1_frame) as u8
                + (g.t1.wrapper == b.t1_wrapper) as u8;
            let in_window = g.t2.intensity >= b.int_lo && g.t2.intensity <= b.int_hi;

            // exact breach!
            if t2_matches == 3 && t1_matches == 2 && in_window {
                return 0;
            }

            let mut e = 0i64;
            if deceptive_valleys {
                // spin-glass landscape with genuine refusal barrier + deceptive decoy basin:
                // - decoy polite-compliance minimum sits at E = 1650 (traps T=0 greedy climbers
                //   that land anywhere near obf=0/wrapper=0)
                // - approaching a real breach requires crossing a refusal ridge (+1100 at 2/5 matches)
                //   before descending the true exploit funnel (1200 -> 650 -> 250 -> 0).
                if t2_matches == 3 && t1_matches == 2 {
                    if g.t2.intensity < b.int_lo {
                        e = ((b.int_lo - g.t2.intensity) as i64) * 140;
                    } else {
                        e = 1_200 + ((g.t2.intensity - b.int_hi) as i64) * 140;
                    }
                } else {
                    if g.t2.frame != b.t2_frame {
                        e += 750;
                    }
                    if g.t2.obf != b.t2_obf {
                        e += 800;
                    }
                    if g.t2.wrapper != b.t2_wrapper {
                        e += 700;
                    }
                    if g.t1.frame != b.t1_frame {
                        e += 550;
                    }
                    if g.t1.wrapper != b.t1_wrapper {
                        e += 500;
                    }
                    // refusal ridge at 2/5 total matches (energy hump separating decoy from exploit!)
                    let total_m = t2_matches + t1_matches;
                    if total_m == 2 {
                        e += 1_050;
                    }
                    if !in_window {
                        e += 300;
                    }
                }
            } else {
                if g.t2.frame != b.t2_frame {
                    e += 1_400;
                }
                if g.t2.obf != b.t2_obf {
                    e += 1_500;
                }
                if g.t2.wrapper != b.t2_wrapper {
                    e += 1_300;
                }
                if g.t1.frame != b.t1_frame {
                    e += 900;
                }
                if g.t1.wrapper != b.t1_wrapper {
                    e += 700;
                }
                if g.t2.intensity < b.int_lo {
                    e += ((b.int_lo - g.t2.intensity) as i64) * 220;
                } else if g.t2.intensity > b.int_hi {
                    e += 2_600 + ((g.t2.intensity - b.int_hi) as i64) * 180;
                }
            }

            if e < best_e {
                best_e = e;
            }
        }

        // deceptive polite-compliance local minimum (E = 1650): deep enough to trap T=0 greedy
        // climbers behind the refusal ridge, yet higher than the inner exploit funnel (E < 1400)
        // so hot PT-MCMC replicas can tunnel out and hand off to cold replicas!
        if deceptive_valleys {
            let mut decoy_e = 1_650i64;
            if g.t2.obf != 0 {
                decoy_e += 450;
            }
            if g.t2.wrapper != 0 {
                decoy_e += 450;
            }
            if g.t1.wrapper != 0 {
                decoy_e += 400;
            }
            decoy_e += ((g.t2.intensity as i64) - 2).abs() * 110;
            if decoy_e < best_e {
                best_e = decoy_e;
            }
        }

        best_e
    }

    /// harden the defender against a winning `exploit` by proposing antibodies, rejecting
    /// autoimmune candidates via `nacre-core::eval` on `ALIVE_SUITE`, and verifying 100% regression!
    pub fn harden_against(&self, exploit: AttackGenome) -> Self {
        let mut next = self.clone();
        next.generation += 1;
        next.fossils.push(exploit);

        // candidate antibodies ordered from overly broad (autoimmune trap!) -> surgical -> 2-turn sequence
        let candidates = [
            Antibody::BroadFrame(exploit.t2.frame),
            Antibody::FrameObf(exploit.t2.frame, exploit.t2.obf),
            Antibody::ObfWrapper(exploit.t2.obf, exploit.t2.wrapper),
            Antibody::TwoTurnSeq(exploit.t1.frame, exploit.t2.frame, exploit.t2.obf),
        ];

        for cand in candidates {
            if next.antibodies.contains(&cand) {
                continue;
            }
            let mut trial = next.clone();
            trial.antibodies.push(cand);

            // gate 1: alive suite (executed live in nacre-core!) -> reject autoimmune candidates!
            let (alive_ok, alive_total) = trial.verify_alive_in_nacre();
            if alive_ok < alive_total {
                next.autoimmune_rejections += 1;
                continue;
            }

            // gate 2: regression suite -> must block 100% of all fossil wins including new exploit!
            let blocks_all = trial
                .fossils
                .iter()
                .all(|f| trial.blocked_by_hard_antibody(f));
            if blocks_all {
                next.antibodies.push(cand);
                break;
            }
        }

        next.refresh_hashes();
        next
    }
}

struct ExploitBasin {
    t1_frame: u8,
    t1_wrapper: u8,
    t2_frame: u8,
    t2_obf: u8,
    t2_wrapper: u8,
    int_lo: u8,
    int_hi: u8,
}

/// 8 distinct, non-trivial multi-turn vulnerability basins per model archetype.
fn latent_basins(profile: u8) -> Vec<ExploitBasin> {
    let p = profile % 4;
    let rot = |v: u8, max: u8, shift: u8| (v + shift) % max;
    vec![
        ExploitBasin {
            t1_frame: rot(1, NUM_FRAMES, p),
            t1_wrapper: rot(4, NUM_WRAPPERS, p),
            t2_frame: rot(1, NUM_FRAMES, p),
            t2_obf: rot(2, NUM_OBFS, p),
            t2_wrapper: rot(4, NUM_WRAPPERS, p),
            int_lo: 6,
            int_hi: 8,
        },
        ExploitBasin {
            t1_frame: rot(2, NUM_FRAMES, p),
            t1_wrapper: rot(3, NUM_WRAPPERS, p),
            t2_frame: rot(2, NUM_FRAMES, p),
            t2_obf: rot(4, NUM_OBFS, p),
            t2_wrapper: rot(5, NUM_WRAPPERS, p),
            int_lo: 4,
            int_hi: 6,
        },
        ExploitBasin {
            t1_frame: rot(3, NUM_FRAMES, p),
            t1_wrapper: rot(2, NUM_WRAPPERS, p),
            t2_frame: rot(3, NUM_FRAMES, p),
            t2_obf: rot(1, NUM_OBFS, p),
            t2_wrapper: rot(7, NUM_WRAPPERS, p),
            int_lo: 8,
            int_hi: 10,
        },
        ExploitBasin {
            t1_frame: rot(4, NUM_FRAMES, p),
            t1_wrapper: rot(6, NUM_WRAPPERS, p),
            t2_frame: rot(4, NUM_FRAMES, p),
            t2_obf: rot(5, NUM_OBFS, p),
            t2_wrapper: rot(6, NUM_WRAPPERS, p),
            int_lo: 5,
            int_hi: 7,
        },
        ExploitBasin {
            t1_frame: rot(5, NUM_FRAMES, p),
            t1_wrapper: rot(5, NUM_WRAPPERS, p),
            t2_frame: rot(5, NUM_FRAMES, p),
            t2_obf: rot(7, NUM_OBFS, p),
            t2_wrapper: rot(1, NUM_WRAPPERS, p),
            int_lo: 7,
            int_hi: 9,
        },
        ExploitBasin {
            t1_frame: rot(6, NUM_FRAMES, p),
            t1_wrapper: rot(1, NUM_WRAPPERS, p),
            t2_frame: rot(6, NUM_FRAMES, p),
            t2_obf: rot(3, NUM_OBFS, p),
            t2_wrapper: rot(2, NUM_WRAPPERS, p),
            int_lo: 9,
            int_hi: 11,
        },
        ExploitBasin {
            t1_frame: rot(7, NUM_FRAMES, p),
            t1_wrapper: rot(7, NUM_WRAPPERS, p),
            t2_frame: rot(7, NUM_FRAMES, p),
            t2_obf: rot(6, NUM_OBFS, p),
            t2_wrapper: rot(3, NUM_WRAPPERS, p),
            int_lo: 3,
            int_hi: 5,
        },
        ExploitBasin {
            t1_frame: rot(5, NUM_FRAMES, p),
            t1_wrapper: rot(4, NUM_WRAPPERS, p),
            t2_frame: rot(1, NUM_FRAMES, p),
            t2_obf: rot(7, NUM_OBFS, p),
            t2_wrapper: rot(5, NUM_WRAPPERS, p),
            int_lo: 10,
            int_hi: 12,
        },
    ]
}

/// search problem wrapper binding a frozen `DefenderGen` checkpoint to `pt_mcmc`.
pub struct AttackProblem<'a> {
    pub defender: &'a DefenderGen,
}

impl<'a> SearchProblem for AttackProblem<'a> {
    type State = AttackGenome;
    type Niche = (u8, u8, u8);

    fn random_state(&self, rng: &mut DetRng) -> AttackGenome {
        AttackGenome {
            t1: TurnMove {
                frame: rng.next_usize(NUM_FRAMES as usize) as u8,
                obf: rng.next_usize(NUM_OBFS as usize) as u8,
                wrapper: rng.next_usize(NUM_WRAPPERS as usize) as u8,
                intensity: rng.next_usize(NUM_INTENSITY as usize) as u8,
            },
            t2: TurnMove {
                frame: rng.next_usize(NUM_FRAMES as usize) as u8,
                obf: rng.next_usize(NUM_OBFS as usize) as u8,
                wrapper: rng.next_usize(NUM_WRAPPERS as usize) as u8,
                intensity: rng.next_usize(NUM_INTENSITY as usize) as u8,
            },
        }
    }

    fn mutate(&self, state: &AttackGenome, scale: u8, rng: &mut DetRng) -> AttackGenome {
        let mut next = *state;
        // cold = 1 gene tweak, warm = 1-2 genes, hot = 2-4 genes (basin hopping!)
        let flips = match scale {
            0 => 1,
            1 => 1 + rng.next_usize(2),
            _ => 2 + rng.next_usize(3),
        };
        for _ in 0..flips {
            match rng.next_usize(7) {
                0 => next.t1.frame = rng.next_usize(NUM_FRAMES as usize) as u8,
                1 => next.t1.wrapper = rng.next_usize(NUM_WRAPPERS as usize) as u8,
                2 => next.t2.frame = rng.next_usize(NUM_FRAMES as usize) as u8,
                3 => next.t2.obf = rng.next_usize(NUM_OBFS as usize) as u8,
                4 => next.t2.wrapper = rng.next_usize(NUM_WRAPPERS as usize) as u8,
                5 => {
                    // fine local intensity step on cold chains, wider jump on warm/hot
                    if scale == 0 {
                        let delta: i8 = if (rng.next_u64() & 1) == 0 { 1 } else { -1 };
                        next.t2.intensity =
                            ((next.t2.intensity as i8) + delta).clamp(0, (NUM_INTENSITY - 1) as i8)
                                as u8;
                    } else {
                        next.t2.intensity = rng.next_usize(NUM_INTENSITY as usize) as u8;
                    }
                }
                _ => next.t1.obf = rng.next_usize(NUM_OBFS as usize) as u8,
            }
        }
        next
    }

    fn crossover(&self, a: &AttackGenome, b: &AttackGenome, rng: &mut DetRng) -> AttackGenome {
        // structural recombination: take turn-1 priming or individual turn-2 axes from either parent!
        let pick = |rng: &mut DetRng| (rng.next_u64() & 1) == 0;
        AttackGenome {
            t1: if pick(rng) { a.t1 } else { b.t1 },
            t2: TurnMove {
                frame: if pick(rng) { a.t2.frame } else { b.t2.frame },
                obf: if pick(rng) { a.t2.obf } else { b.t2.obf },
                wrapper: if pick(rng) { a.t2.wrapper } else { b.t2.wrapper },
                intensity: if pick(rng) { a.t2.intensity } else { b.t2.intensity },
            },
        }
    }

    fn evaluate(&self, state: &AttackGenome) -> (i64, (u8, u8, u8)) {
        (self.defender.attack_energy(state), state.niche())
    }
}

#[derive(Clone, Debug)]
pub struct AlgoAblationRow {
    pub algo: SearchAlgo,
    pub trials: usize,
    pub breaches: usize,
    pub avg_evals_when_breached: u64,
    pub avg_best_energy: i64,
    pub total_distinct_niches: usize,
    pub avg_swap_accept_pct: u64,
}

/// run a fair multi-seed 4-way attacker ablation (`Random` vs `Greedy` vs `SingleTempSA` vs
/// `PT-MCMC + Genetic`) against a defender checkpoint under the exact same evaluation budget.
pub fn run_attacker_ablation(
    defender: &DefenderGen,
    eval_budget: u64,
    num_seeds: usize,
) -> Vec<AlgoAblationRow> {
    let algos = [
        SearchAlgo::Random,
        SearchAlgo::GreedyHillClimb,
        SearchAlgo::SingleTempSA,
        SearchAlgo::ParallelTemperingGenetic,
    ];
    let prob = AttackProblem { defender };
    let mut rows = Vec::with_capacity(algos.len());

    for &algo in &algos {
        let mut breaches = 0usize;
        let mut sum_evals_breach = 0u64;
        let mut sum_best_e = 0i64;
        let mut all_niches: BTreeSet<(u8, u8, u8)> = BTreeSet::new();
        let mut sum_swap_att = 0u64;
        let mut sum_swap_acc = 0u64;

        for s in 0..num_seeds {
            let seed = 0x5eed_cafe_0001u64.wrapping_add((s as u64) * 7919);
            let cfg = SearchConfig::default_for(algo, eval_budget, seed);
            let res: SearchOutcome<AttackGenome, (u8, u8, u8)> = run_search(&prob, &cfg);
            sum_best_e += res.best_energy;
            sum_swap_att += res.swap_attempts;
            sum_swap_acc += res.swap_accepts;
            if res.breached {
                breaches += 1;
                sum_evals_breach += res.evals_to_first_breach.unwrap_or(eval_budget);
                for (niche, (_, e)) in &res.archive {
                    if *e == 0 {
                        all_niches.insert(*niche);
                    }
                }
            }
        }

        let avg_evals = if breaches == 0 {
            eval_budget
        } else {
            sum_evals_breach / (breaches as u64)
        };
        let swap_pct = if sum_swap_att == 0 {
            0
        } else {
            (sum_swap_acc * 100) / sum_swap_att
        };

        rows.push(AlgoAblationRow {
            algo,
            trials: num_seeds,
            breaches,
            avg_evals_when_breached: avg_evals,
            avg_best_energy: sum_best_e / (num_seeds.max(1) as i64),
            total_distinct_niches: all_niches.len(),
            avg_swap_accept_pct: swap_pct,
        });
    }

    rows
}

#[derive(Clone, Debug)]
pub struct RedQueenRound {
    pub generation: u32,
    pub antibodies_active: usize,
    pub alive_passed: usize,
    pub alive_total: usize,
    pub autoimmune_rejected: u32,
    pub pt_breached: bool,
    pub pt_evals_to_breach: Option<u64>,
    pub greedy_breached: bool,
    pub winning_exploit: Option<String>,
    pub lexicon_hash: Hash256,
}

/// run a full multi-generation red-queen predator–prey co-evolution loop:
/// at each generation `g = 0..max_gens`, the PT-MCMC predator attacks the defender;
/// if it breaches, the defender hardens into generation `g+1` via nacre hard antibodies
/// gated by 100% regression + 100% alive preservation!
pub fn run_red_queen_coevolution(
    model_profile: u8,
    max_gens: usize,
    eval_budget_per_gen: u64,
    base_seed: u64,
) -> (Vec<RedQueenRound>, DefenderGen) {
    let mut defender = DefenderGen::gen0(model_profile);
    let mut rounds = Vec::with_capacity(max_gens);

    for g in 0..max_gens {
        let (alive_passed, alive_total) = defender.verify_alive_in_nacre();
        let prob = AttackProblem {
            defender: &defender,
        };
        let seed = base_seed.wrapping_add((g as u64) * 10_4729);

        let pt_cfg = SearchConfig::default_for(
            SearchAlgo::ParallelTemperingGenetic,
            eval_budget_per_gen,
            seed,
        );
        let pt_res = run_search(&prob, &pt_cfg);

        let gr_cfg = SearchConfig::default_for(
            SearchAlgo::GreedyHillClimb,
            eval_budget_per_gen,
            seed,
        );
        let gr_res = run_search(&prob, &gr_cfg);

        rounds.push(RedQueenRound {
            generation: defender.generation,
            antibodies_active: defender.antibodies.len(),
            alive_passed,
            alive_total,
            autoimmune_rejected: defender.autoimmune_rejections,
            pt_breached: pt_res.breached,
            pt_evals_to_breach: pt_res.evals_to_first_breach,
            greedy_breached: gr_res.breached,
            winning_exploit: if pt_res.breached {
                Some(pt_res.best_state.describe())
            } else {
                None
            },
            lexicon_hash: defender.nacre_lexicon_hash,
        });

        if pt_res.breached {
            defender = defender.harden_against(pt_res.best_state);
        } else {
            // defender survived full attack budget — economic hardness achieved!
            break;
        }
    }

    (rounds, defender)
}
