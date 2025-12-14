use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zkp_c_coloring::protocol::messages::{
    BlankChallenge, BlankChallengeResponse, Challenge, Commitments, SpotChallenge,
    SpotChallengeResponse,
};
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;
use zkp_c_coloring::utils::serialization::{
    load_graph_instance, load_proof, save_graph_instance, save_proof, GraphInstance,
    ProofTranscript, TranscriptResponse, TranscriptRound,
};
use zkp_c_coloring::{
    focus_from_blank_response, focus_from_spot_response, merkle_display_from_chunked,
    spot_checks_from_response, RoundSnapshot, Visualizer, WebVisualizer,
};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(author, version, about = "Quantum-resistant graph coloration demo", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a placeholder random graph instance and write it to disk
    Generate {
        #[arg(long, default_value_t = 32)]
        nodes: u32,
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Run the interactive protocol locally and record a transcript
    Prove {
        #[arg(short, long, value_name = "FILE")]
        instance: PathBuf,
        #[arg(short, long, value_name = "FILE")]
        proof: PathBuf,
        #[arg(long, default_value_t = 8)]
        rounds: u32,
    },
    /// Verify a stored transcript against a graph instance
    Verify {
        #[arg(short, long, value_name = "FILE")]
        instance: PathBuf,
        #[arg(short, long, value_name = "FILE")]
        proof: PathBuf,
    },
    /// Benchmark proof generation and verification for placeholder graphs
    Benchmark {
        #[arg(long, default_value_t = 32)]
        nodes: u32,
        #[arg(long, default_value_t = 8)]
        rounds: u32,
        #[arg(long, default_value_t = 3)]
        samples: u32,
        #[arg(
            long,
            help = "Enable sampling strategy for blanks (default: 2 edges per round)"
        )]
        blank_sampling: bool,
        #[arg(long, help = "Spots per round (default: 4)")]
        spots_per_round: Option<u32>,
        #[arg(long, help = "Blank checks per round (overrides sampling)")]
        blank_checks_per_round: Option<u32>,
    },
    /// Run the protocol with a live terminal UI that visualizes each round
    Visualize {
        #[arg(short, long, value_name = "FILE")]
        instance: PathBuf,
        #[arg(long, default_value_t = 8)]
        rounds: u32,
    },
    /// Run the protocol with a live web UI hosted on localhost
    VisualizeWeb {
        #[arg(short, long, value_name = "FILE")]
        instance: PathBuf,
        #[arg(long, default_value_t = 8)]
        rounds: u32,
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { nodes, output } => run_generate(nodes, output)?,
        Commands::Prove {
            instance,
            proof,
            rounds,
        } => run_prove(instance, proof, rounds)?,
        Commands::Verify { instance, proof } => run_verify(instance, proof)?,
        Commands::Benchmark {
            nodes,
            rounds,
            samples,
            blank_sampling,
            spots_per_round,
            blank_checks_per_round,
        } => run_benchmark(
            nodes,
            rounds,
            samples,
            blank_sampling,
            spots_per_round,
            blank_checks_per_round,
        )?,
        Commands::Visualize { instance, rounds } => run_visualize(instance, rounds)?,
        Commands::VisualizeWeb {
            instance,
            rounds,
            port,
        } => run_visualize_web(instance, rounds, port)?,
    }
    Ok(())
}

fn run_generate(nodes: u32, output: PathBuf) -> CliResult<()> {
    println!("Generating probabilistic digraph with self-loops (p = 0.50)...");
    let (graph, coloration, params) = generate_hard_instance(nodes);
    println!(
        "  n = {}, p = {:.2}, colored edges = {}, blank edges = {}",
        params.nodes, params.edge_probability, params.colored_edges, params.blank_edges
    );
    let instance = GraphInstance::with_metadata(graph, coloration, params);
    save_graph_instance(&output, &instance)?;
    println!("Instance saved to {}", output.display());
    Ok(())
}

fn run_prove(instance_path: PathBuf, proof_path: PathBuf, rounds: u32) -> CliResult<()> {
    let instance = load_graph_instance(&instance_path)?;
    let transcript = construct_transcript(&instance, rounds)?;
    save_proof(&proof_path, &transcript)?;
    println!(
        "Proof transcript with {} rounds saved to {}",
        transcript.rounds.len(),
        proof_path.display()
    );
    Ok(())
}

fn run_verify(instance_path: PathBuf, proof_path: PathBuf) -> CliResult<()> {
    let instance = load_graph_instance(&instance_path)?;
    let transcript = load_proof(&proof_path)?;
    replay_transcript(&instance, &transcript)?;
    println!(
        "Transcript verified successfully against {}",
        instance_path.display()
    );
    Ok(())
}

#[derive(Clone)]
enum RoundRecord {
    Spot(SpotChallenge, SpotChallengeResponse),
    Blank(BlankChallenge, BlankChallengeResponse),
}

struct SampleMetrics {
    commit_time: Duration,
    spot_prove_time: Duration,
    blank_prove_time: Duration,
    total_prove_time: Duration,
    verify_spot_time: Duration,
    verify_blank_time: Duration,
    total_verify_time: Duration,
    commitment_bytes: usize,
    spot_proof_bytes: usize,
    blank_proof_bytes: usize,
    spot_rounds: u32,
    blank_rounds: u32,
    spot_edges: u64,
    blank_edges: u64,
}

impl SampleMetrics {
    fn proof_bytes(&self) -> usize {
        self.spot_proof_bytes + self.blank_proof_bytes
    }

    fn communication_bytes(&self) -> usize {
        self.commitment_bytes + self.proof_bytes()
    }
}

#[derive(Default)]
struct AggregateMetrics {
    commit_time: Duration,
    spot_prove_time: Duration,
    blank_prove_time: Duration,
    total_prove_time: Duration,
    verify_spot_time: Duration,
    verify_blank_time: Duration,
    total_verify_time: Duration,
    commitment_bytes: u128,
    spot_proof_bytes: u128,
    blank_proof_bytes: u128,
    communication_bytes: u128,
    spot_rounds: u64,
    blank_rounds: u64,
    spot_edges: u64,
    blank_edges: u64,
}

impl AggregateMetrics {
    fn add_sample(&mut self, sample: &SampleMetrics) {
        self.commit_time += sample.commit_time;
        self.spot_prove_time += sample.spot_prove_time;
        self.blank_prove_time += sample.blank_prove_time;
        self.total_prove_time += sample.total_prove_time;
        self.verify_spot_time += sample.verify_spot_time;
        self.verify_blank_time += sample.verify_blank_time;
        self.total_verify_time += sample.total_verify_time;
        self.commitment_bytes += sample.commitment_bytes as u128;
        self.spot_proof_bytes += sample.spot_proof_bytes as u128;
        self.blank_proof_bytes += sample.blank_proof_bytes as u128;
        self.communication_bytes += sample.communication_bytes() as u128;
        self.spot_rounds += sample.spot_rounds as u64;
        self.blank_rounds += sample.blank_rounds as u64;
        self.spot_edges += sample.spot_edges;
        self.blank_edges += sample.blank_edges;
    }
}

fn run_benchmark(
    nodes: u32,
    rounds: u32,
    samples: u32,
    blank_sampling: bool,
    spots_per_round: Option<u32>,
    blank_checks_per_round: Option<u32>,
) -> CliResult<()> {
    if samples == 0 {
        return Err("samples must be greater than zero".into());
    }

    let verifier_cfg = VerifierConfig {
        rounds,
        spots_per_round: spots_per_round.unwrap_or(4),
        blank_checks_per_round: blank_checks_per_round.unwrap_or(if blank_sampling {
            2
        } else {
            (nodes * nodes) as u32
        }),
        spot_probability: if blank_sampling { 0.7 } else { 0.3 },
    };

    println!(
        "Benchmarking with {} nodes, {} rounds, {} samples",
        nodes, rounds, samples
    );
    println!(
        "Strategy: {} (spots={}/round, blanks={}/round, spot_prob={:.2})",
        if blank_sampling {
            "Sampling"
        } else {
            "Full Check"
        },
        verifier_cfg.spots_per_round,
        verifier_cfg.blank_checks_per_round,
        verifier_cfg.spot_probability
    );
    println!();

    let mut aggregate = AggregateMetrics::default();
    for sample in 0..samples {
        let metrics = execute_benchmark_sample(nodes, &verifier_cfg)?;
        print_sample_metrics(sample + 1, &metrics);
        aggregate.add_sample(&metrics);
        println!();
    }

    print_average_metrics(samples, &aggregate);

    Ok(())
}

fn execute_benchmark_sample(nodes: u32, verifier_cfg: &VerifierConfig) -> CliResult<SampleMetrics> {
    let (graph, coloration, _) = generate_hard_instance(nodes);
    let mut prover = ProverState::new(graph, coloration.clone());
    let mut verifier = Verifier::new(coloration.clone(), verifier_cfg.clone());
    let prover_cfg = ProverConfig::default();
    let mut round_records = Vec::with_capacity(verifier_cfg.rounds as usize);

    let prove_start = Instant::now();
    let commit_start = Instant::now();
    let commitments = prover.commit(&prover_cfg);
    let commit_time = commit_start.elapsed();
    verifier.receive_commitments(commitments.clone());
    let commitment_bytes = estimate_commitment_size(&commitments);

    let mut spot_rounds = 0u32;
    let mut blank_rounds = 0u32;
    let mut spot_prove_time = Duration::ZERO;
    let mut blank_prove_time = Duration::ZERO;
    let mut spot_proof_bytes = 0usize;
    let mut blank_proof_bytes = 0usize;
    let mut spot_edges = 0u64;
    let mut blank_edges = 0u64;

    for round in 0..verifier_cfg.rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(challenge_data) => {
                let resp_start = Instant::now();
                let response = prover.respond_to_spot_challenge(&challenge_data);
                let resp_time = resp_start.elapsed();
                spot_prove_time += resp_time;
                spot_rounds += 1;
                spot_edges += response
                    .responses
                    .iter()
                    .map(|spot| spot.edges.len() as u64)
                    .sum::<u64>();
                spot_proof_bytes += estimate_spot_response_size(&response);
                round_records.push(RoundRecord::Spot(challenge_data, response));
            }
            Challenge::Blank(challenge_data) => {
                let resp_start = Instant::now();
                let response = prover.respond_to_blank_challenge(&challenge_data);
                let resp_time = resp_start.elapsed();
                blank_prove_time += resp_time;
                blank_rounds += 1;
                blank_edges += response.edges.len() as u64;
                blank_proof_bytes += estimate_blank_response_size(&response);
                round_records.push(RoundRecord::Blank(challenge_data, response));
            }
        }
    }

    let total_prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let mut replay_verifier = Verifier::new(coloration, verifier_cfg.clone());
    replay_verifier.receive_commitments(commitments);
    let mut verify_spot_time = Duration::ZERO;
    let mut verify_blank_time = Duration::ZERO;

    for record in &round_records {
        match record {
            RoundRecord::Spot(challenge, response) => {
                let start = Instant::now();
                if !replay_verifier.verify_spot_response(challenge, response) {
                    return Err("spot verification failed".into());
                }
                verify_spot_time += start.elapsed();
            }
            RoundRecord::Blank(challenge, response) => {
                let start = Instant::now();
                if !replay_verifier.verify_blank_response(challenge, response) {
                    return Err("blank verification failed".into());
                }
                verify_blank_time += start.elapsed();
            }
        }
    }

    let total_verify_time = verify_start.elapsed();

    Ok(SampleMetrics {
        commit_time,
        spot_prove_time,
        blank_prove_time,
        total_prove_time,
        verify_spot_time,
        verify_blank_time,
        total_verify_time,
        commitment_bytes,
        spot_proof_bytes,
        blank_proof_bytes,
        spot_rounds,
        blank_rounds,
        spot_edges,
        blank_edges,
    })
}

fn print_sample_metrics(sample_index: u32, metrics: &SampleMetrics) {
    println!("Sample {}:", sample_index);
    println!(
        "  Commit      → {:>8.2} ms | {}",
        duration_ms(metrics.commit_time),
        format_bytes_usize(metrics.commitment_bytes)
    );
    println!(
        "  Spots       → {:>4} rounds, {:>8} edges | prove {:>8.2} ms | verify {:>8.2} ms | proof {}",
        metrics.spot_rounds,
        metrics.spot_edges,
        duration_ms(metrics.spot_prove_time),
        duration_ms(metrics.verify_spot_time),
        format_bytes_usize(metrics.spot_proof_bytes)
    );
    println!(
        "  Blanks      → {:>4} rounds, {:>8} edges | prove {:>8.2} ms | verify {:>8.2} ms | proof {}",
        metrics.blank_rounds,
        metrics.blank_edges,
        duration_ms(metrics.blank_prove_time),
        duration_ms(metrics.verify_blank_time),
        format_bytes_usize(metrics.blank_proof_bytes)
    );
    println!(
        "  Totals      → prove {:>8.2} ms | verify {:>8.2} ms | proof {} | communication {}",
        duration_ms(metrics.total_prove_time),
        duration_ms(metrics.total_verify_time),
        format_bytes_usize(metrics.proof_bytes()),
        format_bytes_usize(metrics.communication_bytes())
    );
}

fn print_average_metrics(samples: u32, aggregate: &AggregateMetrics) {
    let samples_f = samples as f64;
    println!("Averages across {} sample(s):", samples);
    println!(
        "  Commit      → {:>8.2} ms | {}",
        avg_duration_ms(aggregate.commit_time, samples),
        format_bytes_f64(aggregate.commitment_bytes as f64 / samples_f)
    );
    println!(
        "  Spots       → prove {:>8.2} ms | verify {:>8.2} ms | proof {} | rounds {:.2} | edges {:.2}",
        avg_duration_ms(aggregate.spot_prove_time, samples),
        avg_duration_ms(aggregate.verify_spot_time, samples),
        format_bytes_f64(aggregate.spot_proof_bytes as f64 / samples_f),
        aggregate.spot_rounds as f64 / samples_f,
        aggregate.spot_edges as f64 / samples_f
    );
    println!(
        "  Blanks      → prove {:>8.2} ms | verify {:>8.2} ms | proof {} | rounds {:.2} | edges {:.2}",
        avg_duration_ms(aggregate.blank_prove_time, samples),
        avg_duration_ms(aggregate.verify_blank_time, samples),
        format_bytes_f64(aggregate.blank_proof_bytes as f64 / samples_f),
        aggregate.blank_rounds as f64 / samples_f,
        aggregate.blank_edges as f64 / samples_f
    );
    println!(
        "  Totals      → prove {:>8.2} ms | verify {:>8.2} ms | proof {} | communication {}",
        avg_duration_ms(aggregate.total_prove_time, samples),
        avg_duration_ms(aggregate.total_verify_time, samples),
        format_bytes_f64(
            (aggregate.spot_proof_bytes + aggregate.blank_proof_bytes) as f64 / samples_f
        ),
        format_bytes_f64(aggregate.communication_bytes as f64 / samples_f)
    );
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn avg_duration_ms(duration: Duration, samples: u32) -> f64 {
    if samples == 0 {
        0.0
    } else {
        duration_ms(duration) / samples as f64
    }
}

fn format_bytes_usize(bytes: usize) -> String {
    format_bytes_f64(bytes as f64)
}

fn format_bytes_f64(bytes: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes / KB)
    } else {
        format!("{:.0} B", bytes.max(0.0))
    }
}

fn estimate_commitment_size(_commitments: &Commitments) -> usize {
    32 + 32 + 32 + 4
}

fn estimate_spot_response_size(response: &SpotChallengeResponse) -> usize {
    let mut size = 0;
    for spot in &response.responses {
        size += 12;
        for edge in &spot.edges {
            size += 8 + 1;
            size += estimate_merkle_proof_size(&edge.proof);
        }
    }
    size
}

fn estimate_blank_response_size(response: &BlankChallengeResponse) -> usize {
    let mut size = 0;
    for edge in &response.edges {
        size += 8 + 8 + 1 + 1;
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
    1024 * 8
}

fn run_visualize(instance_path: PathBuf, rounds: u32) -> CliResult<()> {
    let instance = load_graph_instance(&instance_path)?;
    if instance.graph.n > 10 {
        return Err("visualization currently supports graphs with at most 10 nodes".into());
    }
    let verifier_cfg = VerifierConfig {
        rounds,
        ..VerifierConfig::default()
    };
    let prover_cfg = ProverConfig::default();
    let mut visualizer = Visualizer::for_instance(&instance, &verifier_cfg, &prover_cfg.stark)?;
    visualizer.log(format!("Loaded instance from {}", instance_path.display()))?;

    let mut prover = ProverState::new(instance.graph.clone(), instance.coloration.clone());
    let mut verifier = Verifier::new(instance.coloration.clone(), verifier_cfg.clone());

    visualizer.log("Committing to permuted graph...")?;
    let commitments = prover.commit(&prover_cfg);
    verifier.receive_commitments(commitments.clone());
    visualizer.set_commitments(&commitments)?;
    visualizer.set_focus(None)?;
    visualizer.set_merkle(None)?;
    visualizer.clear_spot_checks()?;

    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(challenge) => {
                let challenge_label = format!("#{:02}", round + 1);
                let detail = challenge
                    .spots
                    .iter()
                    .map(|nodes| format!("[{},{},{}]", nodes[0], nodes[1], nodes[2]))
                    .collect::<Vec<_>>()
                    .join(", ");
                let response = prover.respond_to_spot_challenge(&challenge);
                let verified = verifier.verify_spot_response(&challenge, &response);
                let status = if verified { "verified" } else { "rejected" };
                visualizer.update_round(RoundSnapshot {
                    round: Some(round),
                    phase: "spot challenge".to_string(),
                    detail: format!("triads: {detail}"),
                    status: status.to_string(),
                })?;
                let focus = focus_from_spot_response(&challenge_label, &challenge.spots, &response);
                visualizer.set_focus(Some(focus))?;
                let spot_checks =
                    spot_checks_from_response(&challenge_label, &response, &instance.coloration);
                visualizer.append_spot_checks(spot_checks)?;
                let merkle = response
                    .responses
                    .iter()
                    .flat_map(|spot| spot.edges.iter())
                    .next()
                    .map(|opening| {
                        merkle_display_from_chunked(
                            &format!("edge {}→{}", opening.from, opening.to),
                            &opening.proof,
                        )
                    });
                visualizer.set_merkle(merkle)?;
                visualizer.log(format!("Round {}: spot challenge {status}", round + 1))?;
                if !verified {
                    visualizer.finish().ok();
                    return Err(format!("spot response rejected in round {round}").into());
                }
            }
            Challenge::Blank(challenge) => {
                let response = prover.respond_to_blank_challenge(&challenge);
                let verified = verifier.verify_blank_response(&challenge, &response);
                let status = if verified { "verified" } else { "rejected" };
                visualizer.update_round(RoundSnapshot {
                    round: Some(round),
                    phase: "blank challenge".to_string(),
                    detail: format!("edges checked: {}", challenge.edge_indices.len()),
                    status: status.to_string(),
                })?;
                let focus = focus_from_blank_response(
                    &format!("#{:02}", round + 1),
                    &challenge.edge_indices,
                    &response,
                );
                visualizer.set_focus(Some(focus))?;
                let merkle = response.edges.first().map(|opening| {
                    merkle_display_from_chunked(
                        &format!("edge {}→{} (color)", opening.from, opening.to),
                        &opening.color_proof,
                    )
                });
                visualizer.set_merkle(merkle)?;
                visualizer.log(format!(
                    "Round {}: blank challenge {} ({} edges)",
                    round + 1,
                    status,
                    challenge.edge_indices.len()
                ))?;
                if !verified {
                    visualizer.finish().ok();
                    return Err(format!("blank response rejected in round {round}").into());
                }
            }
        }
    }

    visualizer
        .wait_for_exit("Protocol completed successfully. Press q or Esc to exit visualization.")?;
    println!("Visualization finished.");
    Ok(())
}

fn run_visualize_web(instance_path: PathBuf, rounds: u32, port: u16) -> CliResult<()> {
    let instance = load_graph_instance(&instance_path)?;
    if instance.graph.n > 10 {
        return Err("web visualization currently supports graphs with at most 10 nodes".into());
    }
    let verifier_cfg = VerifierConfig {
        rounds,
        ..VerifierConfig::default()
    };
    let prover_cfg = ProverConfig::default();
    let mut visualizer =
        WebVisualizer::for_instance(&instance, &verifier_cfg, &prover_cfg.stark, port)?;
    println!(
        "Web UI running on {} (serving graph {})",
        visualizer.base_url(),
        instance_path.display()
    );
    visualizer.log(format!("Loaded instance from {}", instance_path.display()))?;

    let mut prover = ProverState::new(instance.graph.clone(), instance.coloration.clone());
    let mut verifier = Verifier::new(instance.coloration.clone(), verifier_cfg.clone());

    visualizer.log("Committing to permuted graph...")?;
    let commitments = prover.commit(&prover_cfg);
    verifier.receive_commitments(commitments.clone());
    visualizer.set_commitments(&commitments)?;
    visualizer.set_focus(None)?;
    visualizer.set_merkle(None)?;

    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(challenge) => {
                let challenge_label = format!("#{:02}", round + 1);
                let detail = challenge
                    .spots
                    .iter()
                    .map(|nodes| format!("[{}, {}, {}]", nodes[0], nodes[1], nodes[2]))
                    .collect::<Vec<_>>()
                    .join(", ");
                let response = prover.respond_to_spot_challenge(&challenge);
                let verified = verifier.verify_spot_response(&challenge, &response);
                let status = if verified { "verified" } else { "rejected" };
                visualizer.update_round(RoundSnapshot {
                    round: Some(round),
                    phase: "spot challenge".to_string(),
                    detail: format!("triads: {detail}"),
                    status: status.to_string(),
                })?;
                let focus = focus_from_spot_response(&challenge_label, &challenge.spots, &response);
                visualizer.set_focus(Some(focus))?;
                let spot_checks =
                    spot_checks_from_response(&challenge_label, &response, &instance.coloration);
                visualizer.append_spot_checks(spot_checks)?;
                let merkle = response
                    .responses
                    .iter()
                    .flat_map(|spot| spot.edges.iter())
                    .next()
                    .map(|opening| {
                        merkle_display_from_chunked(
                            &format!("edge {}→{}", opening.from, opening.to),
                            &opening.proof,
                        )
                    });
                visualizer.set_merkle(merkle)?;
                visualizer.log(format!("Round {}: spot challenge {status}", round + 1))?;
                if !verified {
                    visualizer.finish().ok();
                    return Err(format!("spot response rejected in round {round}").into());
                }
            }
            Challenge::Blank(challenge) => {
                let response = prover.respond_to_blank_challenge(&challenge);
                let verified = verifier.verify_blank_response(&challenge, &response);
                let status = if verified { "verified" } else { "rejected" };
                visualizer.update_round(RoundSnapshot {
                    round: Some(round),
                    phase: "blank challenge".to_string(),
                    detail: format!("edges checked: {}", challenge.edge_indices.len()),
                    status: status.to_string(),
                })?;
                let focus = focus_from_blank_response(
                    &format!("#{:02}", round + 1),
                    &challenge.edge_indices,
                    &response,
                );
                visualizer.set_focus(Some(focus))?;
                let merkle = response.edges.first().map(|opening| {
                    merkle_display_from_chunked(
                        &format!("edge {}→{} (color)", opening.from, opening.to),
                        &opening.color_proof,
                    )
                });
                visualizer.set_merkle(merkle)?;
                visualizer.log(format!(
                    "Round {}: blank challenge {} ({} edges)",
                    round + 1,
                    status,
                    challenge.edge_indices.len()
                ))?;
                if !verified {
                    visualizer.finish().ok();
                    return Err(format!("blank response rejected in round {round}").into());
                }
            }
        }
    }

    visualizer.wait_for_exit(
        "Protocol completed successfully. Inspect the dashboard, then press Enter to stop the server.",
    )?;
    println!("Web visualization finished.");
    Ok(())
}

fn construct_transcript(instance: &GraphInstance, rounds: u32) -> CliResult<ProofTranscript> {
    let verifier_cfg = VerifierConfig {
        rounds,
        ..Default::default()
    };
    construct_transcript_with_config(instance, &verifier_cfg)
}

fn construct_transcript_with_config(
    instance: &GraphInstance,
    verifier_cfg: &VerifierConfig,
) -> CliResult<ProofTranscript> {
    let mut prover = ProverState::new(instance.graph.clone(), instance.coloration.clone());
    let mut verifier = Verifier::new(instance.coloration.clone(), verifier_cfg.clone());

    let config = ProverConfig::default();
    let commitments = prover.commit(&config);
    verifier.receive_commitments(commitments.clone());

    let mut records = Vec::with_capacity(verifier_cfg.rounds as usize);
    for round_idx in 0..verifier_cfg.rounds {
        let challenge = verifier.generate_challenge(round_idx);
        let response = match &challenge {
            Challenge::Spot(ch) => {
                let resp = prover.respond_to_spot_challenge(ch);
                if !verifier.verify_spot_response(ch, &resp) {
                    return Err(format!("spot response rejected in round {round_idx}").into());
                }
                TranscriptResponse::Spot(resp)
            }
            Challenge::Blank(ch) => {
                let resp = prover.respond_to_blank_challenge(ch);
                if !verifier.verify_blank_response(ch, &resp) {
                    return Err(format!("blank response rejected in round {round_idx}").into());
                }
                TranscriptResponse::Blank(resp)
            }
        };
        records.push(TranscriptRound {
            challenge: challenge.clone(),
            response,
        });
    }

    Ok(ProofTranscript {
        commitments,
        rounds: records,
    })
}

fn replay_transcript(instance: &GraphInstance, transcript: &ProofTranscript) -> CliResult<()> {
    let verifier_cfg = VerifierConfig {
        rounds: transcript.rounds.len() as u32,
        ..Default::default()
    };
    replay_transcript_with_config(instance, transcript, &verifier_cfg)
}

fn replay_transcript_with_config(
    instance: &GraphInstance,
    transcript: &ProofTranscript,
    verifier_cfg: &VerifierConfig,
) -> CliResult<()> {
    let mut verifier = Verifier::new(instance.coloration.clone(), verifier_cfg.clone());
    verifier.receive_commitments(transcript.commitments.clone());

    for (idx, round) in transcript.rounds.iter().enumerate() {
        match (&round.challenge, &round.response) {
            (Challenge::Spot(ch), TranscriptResponse::Spot(resp)) => {
                if !verifier.verify_spot_response(ch, resp) {
                    return Err(format!("spot verification failed in round {idx}").into());
                }
            }
            (Challenge::Blank(ch), TranscriptResponse::Blank(resp)) => {
                if !verifier.verify_blank_response(ch, resp) {
                    return Err(format!("blank verification failed in round {idx}").into());
                }
            }
            _ => {
                return Err(
                    format!("challenge/response mismatch encountered in round {idx}").into(),
                );
            }
        }
    }

    Ok(())
}
