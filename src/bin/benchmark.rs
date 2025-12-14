use clap::Parser;
use std::time::{Duration, Instant};
use zkp_c_coloring::protocol::messages::Challenge;
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;
use zkp_c_coloring::utils::serialization::GraphInstance;

#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::GetCurrentProcess;

struct BenchmarkResult {
    nodes: u32,
    rounds: u32,
    blank_strategy: BlankStrategy,
    commit_time_ms: f64,
    spot_response_time_ms: f64,
    blank_response_time_ms: f64,
    spot_verify_time_ms: f64,
    blank_verify_time_ms: f64,
    prove_time_ms: f64,
    verify_time_ms: f64,
    memory_peak_mb: f64,
    commitment_size_bytes: usize,
    proof_size_bytes: usize,
    spot_proof_size_bytes: usize,
    blank_proof_size_bytes: usize,
    communication_size_bytes: usize,
    spot_challenges: u32,
    blank_challenges: u32,
    total_edges_verified: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BlankStrategy {
    Sampling,
    FullCheck,
}

impl std::fmt::Display for BlankStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlankStrategy::Sampling => write!(f, "Sampling"),
            BlankStrategy::FullCheck => write!(f, "FullCheck"),
        }
    }
}

impl std::str::FromStr for BlankStrategy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "sampling" | "sample" => Ok(BlankStrategy::Sampling),
            "full" | "fullcheck" | "full-check" => Ok(BlankStrategy::FullCheck),
            other => Err(format!("unknown blank strategy '{other}'")),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Comprehensive benchmark runner for the ZKP C-coloring protocol"
)]
struct BenchmarkCli {
    /// Comma-separated list of node counts to benchmark (e.g. 16,32,1000)
    #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(u32))]
    nodes: Option<Vec<u32>>,
    /// Comma-separated list of round counts to benchmark (e.g. 5,10,20)
    #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(u32))]
    rounds: Option<Vec<u32>>,
    /// Comma-separated list of blank strategies (sampling,full)
    #[arg(long, value_delimiter = ',')]
    strategies: Option<Vec<BlankStrategy>>,
    /// Number of spot challenges per round (default: 4)
    #[arg(long)]
    spots_per_round: Option<u32>,
}

fn main() {
    let cli = BenchmarkCli::parse();
    println!("=== ZKP C-Coloring Protocol Benchmark Suite ===\n");

    // Simplified defaults (can be overridden via CLI)
    let node_sizes = cli.nodes.unwrap_or_else(|| vec![10, 16, 32, 64]);
    let round_counts = cli.rounds.unwrap_or_else(|| vec![5, 10]);
    let blank_strategies = cli
        .strategies
        .unwrap_or_else(|| vec![BlankStrategy::Sampling, BlankStrategy::FullCheck]);

    let mut all_results = Vec::new();
    let spots_per_round = cli.spots_per_round.unwrap_or(4);

    for &nodes in &node_sizes {
        for &rounds in &round_counts {
            for &strategy in &blank_strategies {
                println!(
                    "Benchmarking n={} nodes, {} rounds, blank strategy: {}",
                    nodes, rounds, strategy
                );

                match run_benchmark(nodes, rounds, strategy, spots_per_round) {
                    Ok(result) => {
                        print_result(&result);
                        all_results.push(result);
                    }
                    Err(e) => {
                        eprintln!("  ✗ Benchmark failed: {}", e);
                    }
                }
                println!();
            }
        }
    }

    println!("\n=== Summary Report ===\n");
    print_summary_table(&all_results);
    print_scaling_analysis(&all_results);
}

fn run_benchmark(
    nodes: u32,
    rounds: u32,
    blank_strategy: BlankStrategy,
    spots_per_round: u32,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let (graph, coloration, _) = generate_hard_instance(nodes);
    let _instance = GraphInstance::new(graph.clone(), coloration.clone());

    let verifier_cfg = match blank_strategy {
        BlankStrategy::Sampling => VerifierConfig {
            rounds,
            spots_per_round,
            blank_checks_per_round: 2,
            spot_probability: 0.7,
        },
        BlankStrategy::FullCheck => {
            let total_edges = (nodes * nodes) as u32;
            VerifierConfig {
                rounds,
                spots_per_round,
                blank_checks_per_round: total_edges,
                spot_probability: 0.3,
            }
        }
    };
    let prover_cfg = ProverConfig::default();

    let mem_before = get_memory_usage();

    let mut spot_response_time = Duration::ZERO;
    let mut blank_response_time = Duration::ZERO;
    let mut spot_verify_time = Duration::ZERO;
    let mut blank_verify_time = Duration::ZERO;
    let mut spot_proof_size = 0usize;
    let mut blank_proof_size = 0usize;

    let prove_start = Instant::now();
    let mut prover = ProverState::new(graph.clone(), coloration.clone());
    let commit_start = Instant::now();
    let commitments = prover.commit(&prover_cfg);
    let commit_time = commit_start.elapsed();
    let mut verifier = Verifier::new(coloration.clone(), verifier_cfg.clone());
    verifier.receive_commitments(commitments.clone());

    let mut spot_count = 0u32;
    let mut blank_count = 0u32;
    let mut total_edges = 0u32;
    let mut proof_size = 0usize;

    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(ref ch) => {
                spot_count += 1;
                let response_start = Instant::now();
                let response = prover.respond_to_spot_challenge(ch);
                spot_response_time += response_start.elapsed();
                let response_size = estimate_spot_response_size(&response);
                proof_size += response_size;
                spot_proof_size += response_size;
                total_edges += response
                    .responses
                    .iter()
                    .map(|r| r.edges.len() as u32)
                    .sum::<u32>();
                if !verifier.verify_spot_response(ch, &response) {
                    return Err("spot verification failed".into());
                }
            }
            Challenge::Blank(ref ch) => {
                blank_count += 1;
                let response_start = Instant::now();
                let response = prover.respond_to_blank_challenge(ch);
                blank_response_time += response_start.elapsed();
                let response_size = estimate_blank_response_size(&response);
                proof_size += response_size;
                blank_proof_size += response_size;
                total_edges += response.edges.len() as u32;
                if !verifier.verify_blank_response(ch, &response) {
                    return Err("blank verification failed".into());
                }
            }
        }
    }

    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let mut verifier = Verifier::new(coloration.clone(), verifier_cfg.clone());
    verifier.receive_commitments(commitments.clone());
    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(ref ch) => {
                let response = prover.respond_to_spot_challenge(ch);
                let verify_start = Instant::now();
                if !verifier.verify_spot_response(ch, &response) {
                    return Err("spot re-verification failed".into());
                }
                spot_verify_time += verify_start.elapsed();
            }
            Challenge::Blank(ref ch) => {
                let response = prover.respond_to_blank_challenge(ch);
                let verify_start = Instant::now();
                if !verifier.verify_blank_response(ch, &response) {
                    return Err("blank re-verification failed".into());
                }
                blank_verify_time += verify_start.elapsed();
            }
        }
    }
    let verify_time = verify_start.elapsed();

    let mem_after = get_memory_usage();
    let memory_used = (mem_after - mem_before).max(0.0);

    let commitment_size = estimate_commitment_size(&commitments);
    let communication_size = commitment_size + proof_size;

    Ok(BenchmarkResult {
        nodes,
        rounds,
        blank_strategy,
        commit_time_ms: commit_time.as_secs_f64() * 1000.0,
        spot_response_time_ms: spot_response_time.as_secs_f64() * 1000.0,
        blank_response_time_ms: blank_response_time.as_secs_f64() * 1000.0,
        spot_verify_time_ms: spot_verify_time.as_secs_f64() * 1000.0,
        blank_verify_time_ms: blank_verify_time.as_secs_f64() * 1000.0,
        prove_time_ms: prove_time.as_secs_f64() * 1000.0,
        verify_time_ms: verify_time.as_secs_f64() * 1000.0,
        memory_peak_mb: memory_used,
        commitment_size_bytes: commitment_size,
        proof_size_bytes: proof_size,
        spot_proof_size_bytes: spot_proof_size,
        blank_proof_size_bytes: blank_proof_size,
        communication_size_bytes: communication_size,
        spot_challenges: spot_count,
        blank_challenges: blank_count,
        total_edges_verified: total_edges,
    })
}

fn estimate_commitment_size(
    _commitments: &zkp_c_coloring::protocol::messages::Commitments,
) -> usize {
    32 + 32 + 32 + 4 // graph_root + perm_root + blank_root + blank_count
}

fn estimate_spot_response_size(
    response: &zkp_c_coloring::protocol::messages::SpotChallengeResponse,
) -> usize {
    let mut size = 0;
    for spot in &response.responses {
        size += 12; // nodes array
        for edge in &spot.edges {
            size += 8 + 1; // from + to + color
            size += estimate_merkle_proof_size(&edge.proof);
        }
    }
    size
}

fn estimate_blank_response_size(
    response: &zkp_c_coloring::protocol::messages::BlankChallengeResponse,
) -> usize {
    let mut size = 0;
    for edge in &response.edges {
        size += 8 + 8 + 1 + 1; // edge_index + from + to + color + is_blank
        size += estimate_merkle_proof_size(&edge.color_proof);
        size += estimate_merkle_proof_size(&edge.blank_proof);
    }
    size += estimate_stark_proof_size(&response.stark_proof);
    size
}

fn estimate_merkle_proof_size(proof: &zkp_c_coloring::crypto::merkle::ChunkedMerkleProof) -> usize {
    let leaf_path_size = 32 + proof.leaf_proof.path.len() * (32 + 1);
    let chunk_path_size = 32 + proof.chunk_proof.path.len() * (32 + 1);
    leaf_path_size + chunk_path_size
}

fn estimate_stark_proof_size(_proof: &zkp_c_coloring::stark::prover::BlankCountProof) -> usize {
    // Conservative estimate based on FRI layers, queries, and trace commitment
    1024 * 8 // ~8KB for typical STARK proof
}

#[cfg(target_os = "windows")]
fn get_memory_usage() -> f64 {
    unsafe {
        let process = GetCurrentProcess();
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

        if GetProcessMemoryInfo(process, &mut pmc, pmc.cb).is_ok() {
            pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_memory_usage() -> f64 {
    // Fallback for non-Windows systems
    0.0
}

fn print_result(result: &BenchmarkResult) {
    println!("  ✓ Prove time:       {:.2} ms", result.prove_time_ms);
    println!(
        "      commit {:.2} ms · spot {:.2} ms · blank {:.2} ms",
        result.commit_time_ms, result.spot_response_time_ms, result.blank_response_time_ms,
    );
    println!(
        "  ✓ Verify time:      {:.2} ms (spots {:.2} ms, blanks {:.2} ms)",
        result.verify_time_ms, result.spot_verify_time_ms, result.blank_verify_time_ms,
    );
    println!("  ✓ Memory used:      {:.2} MB", result.memory_peak_mb);
    println!(
        "  ✓ Commitment size:  {:.2} KB",
        result.commitment_size_bytes as f64 / 1024.0
    );
    println!(
        "      spot proof {:.2} KB · blank proof {:.2} KB",
        result.spot_proof_size_bytes as f64 / 1024.0,
        result.blank_proof_size_bytes as f64 / 1024.0
    );
    println!(
        "  ✓ Total proof size: {:.2} KB",
        result.proof_size_bytes as f64 / 1024.0
    );
    println!(
        "  ✓ Total communication: {:.2} KB",
        result.communication_size_bytes as f64 / 1024.0
    );
    println!("  ✓ Spot challenges:  {}", result.spot_challenges);
    println!("  ✓ Blank challenges: {}", result.blank_challenges);
    println!("  ✓ Edges verified:   {}", result.total_edges_verified);
}

fn print_summary_table(results: &[BenchmarkResult]) {
    println!(
        "{:<6} {:<7} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
        "Nodes",
        "Rounds",
        "Strategy",
        "Commit(ms)",
        "Spot(ms)",
        "Blank(ms)",
        "Prove(ms)",
        "Verify(ms)",
        "Proof(KB)",
        "Comm(KB)"
    );
    println!("{}", "-".repeat(130));

    for result in results {
        println!(
            "{:<6} {:<7} {:<12} {:<12.2} {:<12.2} {:<12.2} {:<12.2} {:<12.2} {:<12.2} {:<12.2}",
            result.nodes,
            result.rounds,
            result.blank_strategy.to_string(),
            result.commit_time_ms,
            result.spot_response_time_ms,
            result.blank_response_time_ms,
            result.prove_time_ms,
            result.verify_time_ms,
            result.proof_size_bytes as f64 / 1024.0,
            result.communication_size_bytes as f64 / 1024.0
        );
    }
}

fn print_scaling_analysis(results: &[BenchmarkResult]) {
    println!("\n=== Scaling Analysis ===\n");

    // Group by strategy
    for strategy in &[BlankStrategy::Sampling, BlankStrategy::FullCheck] {
        println!("Strategy: {}", strategy);

        let filtered: Vec<_> = results
            .iter()
            .filter(|r| r.blank_strategy == *strategy && r.rounds == 10)
            .collect();

        if filtered.len() >= 2 {
            let first = filtered[0];
            let last = filtered[filtered.len() - 1];

            let prove_ratio = last.prove_time_ms / first.prove_time_ms;
            let verify_ratio = last.verify_time_ms / first.verify_time_ms;
            let proof_ratio = last.proof_size_bytes as f64 / first.proof_size_bytes as f64;

            let node_ratio = last.nodes as f64 / first.nodes as f64;

            println!(
                "  Nodes: {} → {} ({}x increase)",
                first.nodes, last.nodes, node_ratio
            );
            println!("  Prove time scaling:  {:.2}x", prove_ratio);
            println!("  Verify time scaling: {:.2}x", verify_ratio);
            println!("  Proof size scaling:  {:.2}x", proof_ratio);

            let prove_complexity = prove_ratio.log(node_ratio);
            let verify_complexity = verify_ratio.log(node_ratio);

            println!("  Estimated prove complexity: O(n^{:.2})", prove_complexity);
            println!(
                "  Estimated verify complexity: O(n^{:.2})",
                verify_complexity
            );
        }
        println!();
    }

    // Compare sampling vs full check
    println!("Sampling vs Full Check Comparison (64 nodes, 10 rounds):");
    let sampling = results
        .iter()
        .find(|r| r.nodes == 64 && r.rounds == 10 && r.blank_strategy == BlankStrategy::Sampling);
    let full = results
        .iter()
        .find(|r| r.nodes == 64 && r.rounds == 10 && r.blank_strategy == BlankStrategy::FullCheck);

    if let (Some(s), Some(f)) = (sampling, full) {
        println!(
            "  Prove time overhead: {:.2}x",
            f.prove_time_ms / s.prove_time_ms
        );
        println!(
            "  Verify time overhead: {:.2}x",
            f.verify_time_ms / s.verify_time_ms
        );
        println!(
            "  Proof size overhead: {:.2}x",
            f.proof_size_bytes as f64 / s.proof_size_bytes as f64
        );
    }
}
