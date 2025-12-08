use zkp_c_coloring::protocol::messages::Challenge;
use zkp_c_coloring::protocol::prover::{ProverConfig, ProverState};
use zkp_c_coloring::protocol::verifier::{Verifier, VerifierConfig};
use zkp_c_coloring::utils::random_graph::generate_hard_instance;

#[test]
fn graph_generator_tracks_blank_edges() {
    let nodes = 32;
    let (graph, _coloration, params) = generate_hard_instance(nodes);
    assert_eq!(graph.n, nodes);
    assert_eq!(graph.blank_count(), params.blank_edges);
}

#[test]
fn protocol_round_trip_accepts_transcript() {
    let nodes = 24;
    let rounds = 6;
    let (graph, coloration, _params) = generate_hard_instance(nodes);

    let mut prover = ProverState::new(graph.clone(), coloration.clone());
    let mut verifier = Verifier::new(
        coloration,
        VerifierConfig {
            rounds,
            spots_per_round: 3,
            blank_checks_per_round: 2,
            spot_probability: 0.7,
        },
    );

    let config = ProverConfig::default();
    let commitments = prover.commit(&config);
    verifier.receive_commitments(commitments);

    for round in 0..rounds {
        let challenge = verifier.generate_challenge(round);
        match challenge {
            Challenge::Spot(ch) => {
                let response = prover.respond_to_spot_challenge(&ch);
                assert!(
                    verifier.verify_spot_response(&ch, &response),
                    "spot response rejected in round {}",
                    round
                );
            }
            Challenge::Blank(ch) => {
                let response = prover.respond_to_blank_challenge(&ch);
                assert!(
                    verifier.verify_blank_response(&ch, &response),
                    "blank response rejected in round {}",
                    round
                );
            }
        }
    }
}
