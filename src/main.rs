use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zkp_c_coloring::protocol::messages::Challenge;
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;
use zkp_c_coloring::utils::serialization::{
    load_graph_instance,
    load_proof,
    save_graph_instance,
    save_proof,
    GraphInstance,
    ProofTranscript,
    TranscriptResponse,
    TranscriptRound,
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
        Commands::Prove { instance, proof, rounds } => run_prove(instance, proof, rounds)?,
        Commands::Verify { instance, proof } => run_verify(instance, proof)?,
        Commands::Benchmark { nodes, rounds, samples } => run_benchmark(nodes, rounds, samples)?,
    }
    Ok(())
}

fn run_generate(nodes: u32, output: PathBuf) -> CliResult<()> {
    println!("Generating hard-instance graph (tournament/grid embedding)...");
    let (graph, coloration, params) = generate_hard_instance(nodes);
    println!(
        "  n = {}, tournament k = {}, grid = {}x{}, blank budget = {}",
        params.nodes, params.tournament_size, params.grid_rows, params.grid_cols, params.blank_budget
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
    println!("Transcript verified successfully against {}", instance_path.display());
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

fn construct_transcript(instance: &GraphInstance, rounds: u32) -> CliResult<ProofTranscript> {
    let mut prover = ProverState::new(instance.graph.clone(), instance.coloration.clone());
    let mut verifier = Verifier::new(
        instance.coloration.clone(),
        VerifierConfig { rounds, ..Default::default() },
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
                return Err(format!(
                    "challenge/response mismatch encountered in round {idx}"
                )
                .into());
            }
        }
    }

    Ok(())
}
