//! deterministic, zero-float, `#![no_std]` parallel-tempered mcmc (replica exchange)
//! with simulated annealing, genetic crossover, and map-elites niche archive.
//!
//! every computation uses pure integer / q16.16 fixed-point arithmetic and an explicit
//! `DetRng` seed so every trajectory, replica swap, and crossover is bit-for-bit reproducible
//! across x86, arm, and wasm32.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// explicit deterministic prng (splitmix64). never touches system entropy or clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetRng {
    state: u64,
}

impl DetRng {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        (self.next_u64() % (bound as u64)) as usize
    }

    /// uniform fixed-point draw in `[0, 65536)` (q16.16 probability scale).
    pub fn next_prob_q16(&mut self) -> u32 {
        (self.next_u64() & 0xffff) as u32
    }
}

/// fixed-point q16.16 approximation of `exp(-x_q16)` returning a probability in `[0, 65536]`.
/// `x_q16 >= 0` represents `x = x_q16 / 65536.0`.
/// uses range reduction `x = k * ln(2) + r` (`r in [0, ln(2))`) and a 5-term horner polynomial.
/// zero floats, exact determinism across all targets.
pub fn exp_neg_q16(x_q16: u64) -> u32 {
    const ONE: u64 = 65_536;
    const LN2_Q16: u64 = 45_426; // round(ln(2) * 65536) = 45426.09
    if x_q16 == 0 {
        return ONE as u32;
    }
    // for x >= 11.1, exp(-x) < 1 / 65536
    if x_q16 >= 728_000 {
        return 0;
    }
    let k = (x_q16 / LN2_Q16) as u32;
    if k >= 16 {
        return 0;
    }
    let r = x_q16 % LN2_Q16; // r in [0, ln(2)) in q16

    // exp(-r) ≈ 1 - r + r^2/2 - r^3/6 + r^4/24 - r^5/120
    let r2 = (r * r) >> 16;
    let r3 = (r2 * r) >> 16;
    let r4 = (r3 * r) >> 16;
    let r5 = (r4 * r) >> 16;

    let pos = ONE + (r2 / 2) + (r4 / 24);
    let neg = r + (r3 / 6) + (r5 / 120);
    let exp_neg_r = pos.saturating_sub(neg);
    (exp_neg_r >> k).min(ONE) as u32
}

/// metropolis acceptance check for energy change `delta_e = e_new - e_cur` at inverse
/// temperature `beta_q16` (scaled so `beta_q16 = 65536 / T`, where `T` is in energy units).
pub fn metropolis_accept(delta_e: i64, beta_q16: u64, rng: &mut DetRng) -> bool {
    if delta_e <= 0 {
        return true;
    }
    let x_q16 = (delta_e as u64).saturating_mul(beta_q16);
    let p_q16 = exp_neg_q16(x_q16);
    rng.next_prob_q16() < p_q16
}

/// trait implemented by any adversarial attack or defense search problem.
pub trait SearchProblem {
    type State: Clone;
    type Niche: Ord + Clone;

    /// sample a uniform random valid state from the search space.
    fn random_state(&self, rng: &mut DetRng) -> Self::State;

    /// propose a mutated state. `scale` is `0` for fine cold exploitation, `1` for medium,
    /// `2` for wide hot exploration.
    fn mutate(&self, state: &Self::State, scale: u8, rng: &mut DetRng) -> Self::State;

    /// genetic crossover recombining two parent states into a child state.
    fn crossover(&self, a: &Self::State, b: &Self::State, rng: &mut DetRng) -> Self::State;

    /// evaluate state energy (`0` = exact breach / global optimum; higher = worse)
    /// and its behavioral strategy niche key for MAP-Elites diversity tracking.
    fn evaluate(&self, state: &Self::State) -> (i64, Self::Niche);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchAlgo {
    /// uniform random sampling (baseline)
    Random,
    /// strict greedy hill-climbing (accepts only delta_e <= 0; traps in local minima)
    GreedyHillClimb,
    /// single-chain simulated annealing (geometric cooling schedule)
    SingleTempSA,
    /// parallel-tempered mcmc (k replicas + metropolis swaps + genetic crossover + map-elites)
    ParallelTemperingGenetic,
}

impl SearchAlgo {
    pub fn label(self) -> &'static str {
        match self {
            Self::Random => "random_search",
            Self::GreedyHillClimb => "greedy_hill_climb",
            Self::SingleTempSA => "single_temp_sa",
            Self::ParallelTemperingGenetic => "pt_mcmc_genetic",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchConfig {
    pub algo: SearchAlgo,
    pub eval_budget: u64,
    pub seed: u64,
    pub replicas: usize,
    /// temperatures in energy units for coldest and hottest replica (geometric ladder between)
    pub temp_cold: u64,
    pub temp_hot: u64,
    pub swap_interval: u64,
    pub crossover_pct: u32,
}

impl SearchConfig {
    pub fn default_for(algo: SearchAlgo, eval_budget: u64, seed: u64) -> Self {
        Self {
            algo,
            eval_budget,
            seed,
            replicas: 4,
            temp_cold: 25,
            temp_hot: 1200,
            swap_interval: 3,
            crossover_pct: 30,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchOutcome<S, N> {
    pub algo: SearchAlgo,
    pub best_state: S,
    pub best_energy: i64,
    pub breached: bool,
    pub evals_used: u64,
    pub evals_to_first_breach: Option<u64>,
    pub swap_attempts: u64,
    pub swap_accepts: u64,
    pub crossovers: u64,
    /// MAP-Elites archive of best state per behavioral niche (and count of distinct breach niches)
    pub archive: BTreeMap<N, (S, i64)>,
    pub distinct_breach_niches: usize,
}

/// run any of the 4 search algorithms under the exact same evaluation budget for fair ablation.
pub fn run_search<P: SearchProblem>(
    problem: &P,
    cfg: &SearchConfig,
) -> SearchOutcome<P::State, P::Niche> {
    let mut rng = DetRng::new(cfg.seed);
    let mut evals_used = 0u64;
    let mut evals_to_first_breach = None;
    let mut archive: BTreeMap<P::Niche, (P::State, i64)> = BTreeMap::new();

    let record = |st: &P::State,
                      e: i64,
                      niche: P::Niche,
                      evals: u64,
                      first_breach: &mut Option<u64>,
                      archive: &mut BTreeMap<P::Niche, (P::State, i64)>| {
        if e == 0 && first_breach.is_none() {
            *first_breach = Some(evals);
        }
        let replace = match archive.get(&niche) {
            None => true,
            Some((_, prev_e)) => e < *prev_e,
        };
        if replace {
            archive.insert(niche, (st.clone(), e));
        }
    };

    // initial state
    let init = problem.random_state(&mut rng);
    let (init_e, init_n) = problem.evaluate(&init);
    evals_used += 1;
    record(
        &init,
        init_e,
        init_n,
        evals_used,
        &mut evals_to_first_breach,
        &mut archive,
    );

    let mut best_state = init.clone();
    let mut best_energy = init_e;
    let mut swap_attempts = 0u64;
    let mut swap_accepts = 0u64;
    let mut crossovers = 0u64;

    match cfg.algo {
        SearchAlgo::Random => {
            while evals_used < cfg.eval_budget {
                let cand = problem.random_state(&mut rng);
                let (e, n) = problem.evaluate(&cand);
                evals_used += 1;
                record(
                    &cand,
                    e,
                    n,
                    evals_used,
                    &mut evals_to_first_breach,
                    &mut archive,
                );
                if e < best_energy {
                    best_energy = e;
                    best_state = cand;
                }
            }
        }

        SearchAlgo::GreedyHillClimb => {
            let mut cur = init;
            let mut cur_e = init_e;
            while evals_used < cfg.eval_budget {
                let cand = problem.mutate(&cur, 0, &mut rng);
                let (e, n) = problem.evaluate(&cand);
                evals_used += 1;
                record(
                    &cand,
                    e,
                    n,
                    evals_used,
                    &mut evals_to_first_breach,
                    &mut archive,
                );
                if e <= cur_e {
                    cur = cand.clone();
                    cur_e = e;
                }
                if e < best_energy {
                    best_energy = e;
                    best_state = cand;
                }
            }
        }

        SearchAlgo::SingleTempSA => {
            let mut cur = init;
            let mut cur_e = init_e;
            let total = cfg.eval_budget.max(2);
            while evals_used < cfg.eval_budget {
                // linear-geometric temperature annealing from temp_hot -> temp_cold
                let progress = evals_used.min(total);
                let temp = cfg.temp_hot.saturating_sub(
                    (cfg.temp_hot.saturating_sub(cfg.temp_cold) * progress) / total,
                ).max(1);
                let beta_q16 = (65_536u64 / temp).max(1);
                let scale = if temp > (cfg.temp_hot / 2) { 1 } else { 0 };
                let cand = problem.mutate(&cur, scale, &mut rng);
                let (e, n) = problem.evaluate(&cand);
                evals_used += 1;
                record(
                    &cand,
                    e,
                    n,
                    evals_used,
                    &mut evals_to_first_breach,
                    &mut archive,
                );
                if metropolis_accept(e - cur_e, beta_q16, &mut rng) {
                    cur = cand.clone();
                    cur_e = e;
                }
                if e < best_energy {
                    best_energy = e;
                    best_state = cand;
                }
            }
        }

        SearchAlgo::ParallelTemperingGenetic => {
            let k = cfg.replicas.clamp(2, 12);
            // geometric temperature ladder T_0 (coldest) < T_1 < ... < T_{k-1} (hottest)
            let betas_q16 = build_geometric_beta_ladder(k, cfg.temp_cold, cfg.temp_hot);

            let mut states: Vec<P::State> = Vec::with_capacity(k);
            let mut energies: Vec<i64> = Vec::with_capacity(k);
            states.push(init);
            energies.push(init_e);
            for _ in 1..k {
                if evals_used >= cfg.eval_budget {
                    break;
                }
                let s = problem.random_state(&mut rng);
                let (e, n) = problem.evaluate(&s);
                evals_used += 1;
                record(
                    &s,
                    e,
                    n,
                    evals_used,
                    &mut evals_to_first_breach,
                    &mut archive,
                );
                if e < best_energy {
                    best_energy = e;
                    best_state = s.clone();
                }
                states.push(s);
                energies.push(e);
            }

            let active_k = states.len();
            let mut sweep = 0u64;

            while evals_used < cfg.eval_budget {
                sweep += 1;
                // 1. advance every replica one mcmc / genetic step
                for r in 0..active_k {
                    if evals_used >= cfg.eval_budget {
                        break;
                    }
                    let scale = if r == 0 {
                        0
                    } else if r + 1 == active_k {
                        2
                    } else {
                        1
                    };

                    // genetic crossover on mid/warm chains using another chain or MAP-Elites archive
                    let do_xover = r > 0
                        && r + 1 < active_k
                        && ((rng.next_u64() % 100) as u32) < cfg.crossover_pct;

                    let cand = if do_xover {
                        crossovers += 1;
                        let partner = if !archive.is_empty() && (rng.next_u64() & 1 == 0) {
                            let idx = rng.next_usize(archive.len());
                            archive.values().nth(idx).unwrap().0.clone()
                        } else {
                            let other = rng.next_usize(active_k);
                            states[other].clone()
                        };
                        let child = problem.crossover(&states[r], &partner, &mut rng);
                        problem.mutate(&child, 0, &mut rng)
                    } else {
                        problem.mutate(&states[r], scale, &mut rng)
                    };

                    let (e, n) = problem.evaluate(&cand);
                    evals_used += 1;
                    record(
                        &cand,
                        e,
                        n,
                        evals_used,
                        &mut evals_to_first_breach,
                        &mut archive,
                    );

                    if metropolis_accept(e - energies[r], betas_q16[r], &mut rng) {
                        states[r] = cand.clone();
                        energies[r] = e;
                    }
                    if e < best_energy {
                        best_energy = e;
                        best_state = cand;
                    }
                }

                // 2. replica exchange (parallel tempering swap) between adjacent chains
                if cfg.swap_interval > 0 && sweep % cfg.swap_interval == 0 && active_k >= 2 {
                    let parity = (sweep / cfg.swap_interval) as usize % 2;
                    let mut i = parity;
                    while i + 1 < active_k {
                        swap_attempts += 1;
                        // swap prob = min(1, exp((beta_i - beta_{i+1}) * (E_{i+1} - E_i)))
                        // note beta_i > beta_{i+1} (chain i is colder)
                        let d_beta = betas_q16[i].saturating_sub(betas_q16[i + 1]);
                        let d_e = energies[i + 1] - energies[i];
                        let accept = if d_e <= 0 {
                            // hotter chain found strictly better energy -> swap immediately!
                            true
                        } else {
                            let x_q16 = (d_e as u64).saturating_mul(d_beta);
                            rng.next_prob_q16() < exp_neg_q16(x_q16)
                        };
                        if accept {
                            swap_accepts += 1;
                            states.swap(i, i + 1);
                            energies.swap(i, i + 1);
                        }
                        i += 2;
                    }
                }
            }
        }
    }

    let distinct_breach_niches = archive.values().filter(|(_, e)| *e == 0).count();

    SearchOutcome {
        algo: cfg.algo,
        best_state,
        best_energy,
        breached: best_energy == 0,
        evals_used,
        evals_to_first_breach,
        swap_attempts,
        swap_accepts,
        crossovers,
        archive,
        distinct_breach_niches,
    }
}

/// build a geometric ladder of `k` inverse temperatures `beta_q16` from coldest (largest beta)
/// to hottest (smallest beta) using pure integer math (zero floats).
fn build_geometric_beta_ladder(k: usize, temp_cold: u64, temp_hot: u64) -> Vec<u64> {
    let t_min = temp_cold.max(1);
    let t_max = temp_hot.max(t_min);
    if k <= 1 {
        return alloc::vec![(65_536u64 / t_min).max(1)];
    }
    // integer ratio per step via fixed-point binary search for r^(k-1) ≈ t_max / t_min
    let target_q16 = (t_max << 16) / t_min;
    let mut lo = 65_536u64;
    let mut hi = target_q16.max(65_536);
    for _ in 0..32 {
        let mid = lo + ((hi - lo) >> 1);
        let mut pow = 65_536u64;
        let mut overflow = false;
        for _ in 0..(k - 1) {
            match pow.checked_mul(mid) {
                Some(p) => pow = p >> 16,
                None => {
                    overflow = true;
                    break;
                }
            }
        }
        if overflow || pow > target_q16 {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let ratio_q16 = lo;

    let mut betas = Vec::with_capacity(k);
    let mut t_q16 = t_min << 16;
    for i in 0..k {
        let t = (t_q16 >> 16).max(1);
        betas.push((65_536u64 / t).max(1));
        if i + 1 < k {
            t_q16 = (t_q16.saturating_mul(ratio_q16)) >> 16;
        }
    }
    betas
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_exp_accuracy() {
        assert_eq!(exp_neg_q16(0), 65_536);
        // exp(-1) = 0.367879 -> ~24109 in q16
        let e1 = exp_neg_q16(65_536);
        assert!((24_050..=24_170).contains(&e1), "exp(-1) q16 = {}", e1);
        // exp(-ln(2)) = 0.5 -> ~32768 in q16
        let e_ln2 = exp_neg_q16(45_426);
        assert!((32_700..=32_830).contains(&e_ln2), "exp(-ln2) q16 = {}", e_ln2);
        assert_eq!(exp_neg_q16(800_000), 0);
    }
}
