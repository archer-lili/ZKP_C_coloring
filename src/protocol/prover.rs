use crate::crypto::hash::{default_quantum_hash, Blake3QuantumHash, QuantumHash};
use crate::crypto::merkle::{ChunkedMerkleTree, GraphMerkleTree, MerkleTree};
use crate::crypto::polynomial::BlankPolynomial;
use crate::graph::{Color, ColorationSet, Graph};
use crate::protocol::messages::{
    BlankChallenge,
    BlankChallengeResponse,
    BlankEdgeOpening,
    Commitments,
    SpotChallenge,
    SpotChallengeResponse,
    SpotEdgeOpening,
    SpotResponse,
};
use crate::stark::constraints::BlankCountConstraints;
use crate::stark::prover::{generate_blank_count_proof, BlankCountProof, StarkParameters};
use crate::stark::StarkField;
use crate::utils::permutation::random_permutation;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    pub stark: StarkParameters,
}

impl Default for ProverConfig {
    fn default() -> Self {
        ProverConfig {
            stark: StarkParameters::default(),
        }
    }
}

pub struct ProverState {
    pub original_graph: Graph,
    pub coloration_set: ColorationSet,
    hasher: Blake3QuantumHash,
    permutation: Vec<u32>,
    permuted_graph: Graph,
    blank_polynomial: Option<BlankPolynomial>,
    stark_proof: Option<BlankCountProof>,
    commitments: Option<Commitments>,
    graph_tree: Option<GraphMerkleTree>,
    permutation_tree: Option<MerkleTree>,
    blank_tree: Option<ChunkedMerkleTree>,
}

impl ProverState {
    pub fn new(graph: Graph, coloration_set: ColorationSet) -> Self {
        let permuted_graph = graph.clone();
        ProverState {
            original_graph: graph,
            coloration_set,
            hasher: default_quantum_hash(),
            permutation: Vec::new(),
            permuted_graph,
            blank_polynomial: None,
            stark_proof: None,
            commitments: None,
            graph_tree: None,
            permutation_tree: None,
            blank_tree: None,
        }
    }

    pub fn commit(&mut self, config: &ProverConfig) -> Commitments {
        let n = self.original_graph.n;
        self.permutation = random_permutation(n as usize);
        self.permuted_graph = self.original_graph.apply_permutation(&self.permutation);

        let graph_merkle = GraphMerkleTree::from_graph(&self.permuted_graph, &self.hasher);
        let graph_root = graph_merkle.root();
        self.graph_tree = Some(graph_merkle);

        let perm_data: Vec<Vec<u8>> = self
            .permutation
            .iter()
            .map(|value| value.to_be_bytes().to_vec())
            .collect();
        let perm_tree = MerkleTree::new(&perm_data, &self.hasher);
        let permutation_root = perm_tree.root();
        self.permutation_tree = Some(perm_tree);

        let blank_vector = self.build_blank_vector();
        let blank_chunks: Vec<Vec<u8>> = blank_vector.iter().map(|&bit| vec![bit]).collect();
        let blank_tree = ChunkedMerkleTree::new(&blank_chunks, &self.hasher, config.stark.chunk_size);
        let blank_root = blank_tree.root();
        self.blank_tree = Some(blank_tree);

        let polynomial = BlankPolynomial::new(blank_vector);
        let constraints = BlankCountConstraints::<StarkField>::new(n, self.coloration_set.blank_limit() as u64);
        let proof = generate_blank_count_proof(&polynomial, &constraints, &config.stark, &self.hasher);

        self.blank_polynomial = Some(polynomial);
        self.stark_proof = Some(proof.clone());

        let commitments = Commitments {
            graph_root,
            permutation_root,
            blank_root,
            blank_count: self.coloration_set.blank_limit(),
        };

        self.commitments = Some(commitments.clone());
        commitments
    }

    pub fn respond_to_spot_challenge(&self, challenge: &SpotChallenge) -> SpotChallengeResponse {
        let graph_tree = self
            .graph_tree
            .as_ref()
            .expect("commitments must be generated before responding to challenges");
        let mut responses = Vec::new();
        for nodes in &challenge.spots {
            let mut edges = Vec::new();
            for &a in nodes.iter() {
                for &b in nodes.iter() {
                    let color = self.permuted_graph.get_edge(a, b);
                    let proof = graph_tree
                        .get_edge_proof(a, b)
                        .expect("edge proof must exist inside graph commitment");
                    #[cfg(debug_assertions)]
                    {
                        let mut bytes = Vec::with_capacity(9);
                        bytes.extend_from_slice(&a.to_be_bytes());
                        bytes.extend_from_slice(&b.to_be_bytes());
                        bytes.push(color.to_u8());
                        let expected = self.hasher.hash(&bytes);
                        debug_assert_eq!(
                            proof.leaf_proof.leaf_hash,
                            expected,
                            "edge proof hash mismatch for ({}, {})",
                            a,
                            b
                        );
                    }
                    edges.push(SpotEdgeOpening {
                        from: a,
                        to: b,
                        color,
                        proof,
                    });
                }
            }
            responses.push(SpotResponse {
                nodes: *nodes,
                edges,
            });
        }

        SpotChallengeResponse { responses }
    }

    pub fn respond_to_blank_challenge(
        &self,
        challenge: &BlankChallenge,
    ) -> BlankChallengeResponse {
        let graph_tree = self
            .graph_tree
            .as_ref()
            .expect("graph tree available after commitment");
        let blank_tree = self
            .blank_tree
            .as_ref()
            .expect("blank tree available after commitment");
        let n = self.permuted_graph.n as u64;
        let mut edges = Vec::new();
        for &idx in &challenge.edge_indices {
            let i = (idx / n) as u32;
            let j = (idx % n) as u32;
            let color = self.permuted_graph.get_edge(i, j);
            let is_blank = color == Color::Blank;
            let color_proof = graph_tree
                .get_edge_proof(i, j)
                .expect("color proof exists for committed edge");
            let leaf_index = usize::try_from(idx).expect("edge index fits usize on target");
            let blank_proof = blank_tree
                .get_proof(leaf_index)
                .expect("blank vector proof exists for committed edge");
            edges.push(BlankEdgeOpening {
                edge_index: idx,
                from: i,
                to: j,
                color,
                is_blank,
                color_proof,
                blank_proof,
            });
        }

        let stark = self
            .stark_proof
            .as_ref()
            .expect("stark proof generated during commitment")
            .clone();

        BlankChallengeResponse {
            edges,
            stark_proof: stark,
        }
    }

    fn build_blank_vector(&self) -> Vec<u8> {
        let n = self.permuted_graph.n;
        let mut vector = Vec::with_capacity((n * n) as usize);
        for i in 0..n {
            for j in 0..n {
                let is_blank = self.permuted_graph.get_edge(i, j) == Color::Blank;
                vector.push(if is_blank { 1 } else { 0 });
            }
        }
        vector
    }
}
