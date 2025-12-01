use zkp_c_coloring::graph::{Color, ColorationSet, Graph};
use zkp_c_coloring::protocol::messages::Challenge;
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;

fn run_round_trip(nodes: u32, rounds: u32, spots: u32, blanks: u32, spot_prob: f64) {
    let (graph, coloration, _params) = generate_hard_instance(nodes);
    run_round_trip_with_instance(graph, coloration, rounds, spots, blanks, spot_prob);
}

fn run_round_trip_with_instance(
    graph: Graph,
    coloration: ColorationSet,
    rounds: u32,
    spots: u32,
    blanks: u32,
    spot_prob: f64,
) {
    let mut prover = ProverState::new(graph, coloration.clone());
    let mut verifier = Verifier::new(
        coloration,
        VerifierConfig {
            rounds,
            spots_per_round: spots,
            blank_checks_per_round: blanks,
            spot_probability: spot_prob,
        },
    );

    let config = ProverConfig::default();
    let commitments = prover.commit(&config);
    verifier.receive_commitments(commitments);

    for round in 0..rounds {
        match verifier.generate_challenge(round) {
            Challenge::Spot(challenge) => {
                let response = prover.respond_to_spot_challenge(&challenge);
                assert!(
                    verifier.verify_spot_response(&challenge, &response),
                    "spot response rejected in round {round}"
                );
            }
            Challenge::Blank(challenge) => {
                let response = prover.respond_to_blank_challenge(&challenge);
                assert!(
                    verifier.verify_blank_response(&challenge, &response),
                    "blank response rejected in round {round}"
                );
            }
        }
    }
}

fn build_specific_coloring_c(nodes: u32) -> (Graph, ColorationSet) {
    assert!(nodes >= 3, "coloring c requires at least a triad");
    let mut graph = Graph::new(nodes);
    for i in 0..nodes {
        for j in 0..nodes {
            let color = if i == j || (i + j) % 11 == 0 {
                Color::Blank
            } else {
                match (i + 2 * j) % 3 {
                    0 => Color::Red,
                    1 => Color::Green,
                    _ => Color::Yellow,
                }
            };
            graph.set_edge(i, j, color);
        }
    }
    let coloration = ColorationSet::from_graph(&graph);
    (graph, coloration)
}

#[cfg_attr(
    not(feature = "stress-tests"),
    ignore = "set --features stress-tests to enable large-node runs"
)]
#[cfg_attr(
    feature = "stress-tests",
    ignore = "pass -- --ignored to execute heavy stress scenarios"
)]
#[test]
fn protocol_round_trip_accepts_64_nodes() {
    run_round_trip(64, 12, 6, 4, 0.75);
}

#[cfg_attr(
    not(feature = "stress-tests"),
    ignore = "set --features stress-tests to enable large-node runs"
)]
#[cfg_attr(
    feature = "stress-tests",
    ignore = "pass -- --ignored to execute heavy stress scenarios"
)]
#[test]
fn protocol_round_trip_accepts_128_nodes() {
    run_round_trip(128, 16, 8, 6, 0.7);
}

#[cfg_attr(
    not(feature = "stress-tests"),
    ignore = "set --features stress-tests to enable large-node runs"
)]
#[cfg_attr(
    feature = "stress-tests",
    ignore = "pass -- --ignored to execute heavy stress scenarios"
)]
#[test]
fn protocol_round_trip_accepts_specific_coloring_c_on_100_nodes() {
    let (graph, coloration) = build_specific_coloring_c(100);
    run_round_trip_with_instance(graph, coloration, 14, 7, 5, 0.72);
}
