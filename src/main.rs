use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zkp_c_coloring::protocol::messages::Challenge;
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;
use zkp_c_coloring::utils::serialization::{
    load_graph_instance, load_proof, save_graph_instance, save_proof, GraphInstance,
    ProofTranscript, TranscriptResponse, TranscriptRound,
};
use zkp_c_coloring::{
    focus_from_blank_response, focus_from_spot_response, merkle_display_from_chunked,
    RoundSnapshot, Visualizer, WebVisualizer,
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
        } => run_benchmark(nodes, rounds, samples)?,
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
    println!("Generating hard-instance graph (tournament/grid embedding)...");
    let (graph, coloration, params) = generate_hard_instance(nodes);
    println!(
        "  n = {}, tournament k = {}, grid = {}x{}, blank budget = {}",
        params.nodes,
        params.tournament_size,
        params.grid_rows,
        params.grid_cols,
        params.blank_budget
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

fn run_benchmark(nodes: u32, rounds: u32, samples: u32) -> CliResult<()> {
    if samples == 0 {
        return Err("samples must be greater than zero".into());
    }

    let mut total_prove = Duration::ZERO;
    let mut total_verify = Duration::ZERO;
    for sample in 0..samples {
        let (graph, coloration, _) = generate_hard_instance(nodes);
        let instance = GraphInstance::new(graph, coloration);

        let start_prove = Instant::now();
        let transcript = construct_transcript(&instance, rounds)?;
        let prove_time = start_prove.elapsed();
        total_prove += prove_time;

        let start_verify = Instant::now();
        replay_transcript(&instance, &transcript)?;
        let verify_time = start_verify.elapsed();
        total_verify += verify_time;

        println!(
            "Sample {} → prove {:.2} ms, verify {:.2} ms",
            sample + 1,
            prove_time.as_secs_f64() * 1_000.0,
            verify_time.as_secs_f64() * 1_000.0
        );
    }

    let samples_f = samples as f64;
    println!(
        "Average prove time: {:.2} ms",
        (total_prove.as_secs_f64() * 1_000.0) / samples_f
    );
    println!(
        "Average verify time: {:.2} ms",
        (total_verify.as_secs_f64() * 1_000.0) / samples_f
    );

    Ok(())
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

    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(challenge) => {
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
                let focus = focus_from_spot_response(
                    &format!("#{:02}", round + 1),
                    &challenge.spots,
                    &response,
                );
                visualizer.set_focus(Some(focus))?;
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
                let focus = focus_from_spot_response(
                    &format!("#{:02}", round + 1),
                    &challenge.spots,
                    &response,
                );
                visualizer.set_focus(Some(focus))?;
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
    let mut prover = ProverState::new(instance.graph.clone(), instance.coloration.clone());
    let mut verifier = Verifier::new(
        instance.coloration.clone(),
        VerifierConfig {
            rounds,
            ..Default::default()
        },
    );

    let config = ProverConfig::default();
    let commitments = prover.commit(&config);
    verifier.receive_commitments(commitments.clone());

    let mut records = Vec::with_capacity(rounds as usize);
    for round_idx in 0..rounds {
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
    let mut verifier = Verifier::new(
        instance.coloration.clone(),
        VerifierConfig {
            rounds: transcript.rounds.len() as u32,
            ..Default::default()
        },
    );
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
