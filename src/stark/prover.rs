use crate::crypto::hash::QuantumHash;
use crate::crypto::merkle::{ChunkedMerkleProof, ChunkedMerkleTree};
use crate::crypto::polynomial::BlankPolynomial;
use crate::stark::constraints::BlankCountConstraints;
use crate::stark::fri::{derive_fri_layers, sample_fri_queries, FriProof};
use crate::stark::StarkField;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkParameters {
    pub security_level: u32,
    pub num_queries: u32,
    pub chunk_size: usize,
}

impl Default for StarkParameters {
    fn default() -> Self {
        StarkParameters {
            security_level: 128,
            num_queries: 32,
            chunk_size: 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlankCountProof {
    pub trace_root: [u8; 32],
    pub fri_proof: FriProof,
    pub queries: Vec<BlankQuery>,
    pub final_row: TraceRowOpening,
    pub total_sum: u64,
    pub trace_length: u64,
}

impl BlankCountProof {
    pub fn verify(
        &self,
        constraints: &BlankCountConstraints<StarkField>,
        hasher: &dyn QuantumHash,
    ) -> bool {
        if self.total_sum != constraints.expected_sum {
            debug_stark("stark verify failed: total sum mismatch");
            return false;
        }

        let expected_layers =
            derive_fri_layers(self.trace_length as usize, &self.trace_root, hasher);
        if expected_layers != self.fri_proof.layer_roots {
            debug_stark("stark verify failed: layer roots mismatch");
            return false;
        }

        if self.fri_proof.query_positions.len() != self.queries.len() {
            debug_stark("stark verify failed: query length mismatch");
            return false;
        }

        for (position, query) in self
            .fri_proof
            .query_positions
            .iter()
            .copied()
            .zip(&self.queries)
        {
            if query.position != position || position >= self.trace_length {
                debug_stark("stark verify failed: query position invalid");
                return false;
            }
            if !query.current.verify(&self.trace_root, hasher) {
                debug_stark("stark verify failed: current row merkle mismatch");
                return false;
            }
            if query.current.value > 1 {
                debug_stark("stark verify failed: query value not binary");
                return false;
            }
            match &query.previous {
                Some(prev) => {
                    if prev.index + 1 != query.current.index {
                        debug_stark("stark verify failed: previous index mismatch");
                        return false;
                    }
                    if !prev.verify(&self.trace_root, hasher) {
                        debug_stark("stark verify failed: previous row merkle mismatch");
                        return false;
                    }
                    if query.current.running_sum != prev.running_sum + query.current.value as u64 {
                        debug_stark("stark verify failed: running sum mismatch");
                        return false;
                    }
                }
                None => {
                    if query.current.index != 0
                        || query.current.running_sum != query.current.value as u64
                    {
                        debug_stark("stark verify failed: initial row mismatch");
                        return false;
                    }
                }
            }
        }

        if self.final_row.index + 1 != self.trace_length {
            debug_stark("stark verify failed: final row index mismatch");
            return false;
        }
        if !self.final_row.verify(&self.trace_root, hasher) {
            debug_stark("stark verify failed: final row merkle mismatch");
            return false;
        }
        if self.final_row.running_sum != self.total_sum {
            debug_stark("stark verify failed: final sum mismatch");
            return false;
        }

        true
    }
}

pub fn generate_blank_count_proof(
    polynomial: &BlankPolynomial,
    constraints: &BlankCountConstraints<StarkField>,
    params: &StarkParameters,
    hasher: &dyn QuantumHash,
) -> BlankCountProof {
    let _ = constraints.check(polynomial);

    let trace_rows = build_trace_rows(polynomial);
    let serialized_rows: Vec<Vec<u8>> = trace_rows.iter().map(serialize_trace_row).collect();
    let trace_tree = ChunkedMerkleTree::new(&serialized_rows, hasher, params.chunk_size);
    let trace_root = trace_tree.root();
    let trace_length = trace_rows.len() as u64;

    let layer_roots = derive_fri_layers(trace_rows.len(), &trace_root, hasher);
    let query_positions = sample_fri_queries(
        trace_rows.len(),
        &trace_root,
        params.num_queries.max(1) as usize,
        hasher,
    );
    let queries = query_positions
        .iter()
        .map(|&pos| build_query(pos as usize, &trace_rows, &trace_tree))
        .collect();
    let final_row = build_row_opening(trace_rows.len() - 1, &trace_rows, &trace_tree);

    BlankCountProof {
        trace_root,
        fri_proof: FriProof {
            layer_roots,
            query_positions,
        },
        queries,
        final_row,
        total_sum: polynomial.sum(),
        trace_length,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRowOpening {
    pub index: u64,
    pub value: u8,
    pub running_sum: u64,
    pub proof: ChunkedMerkleProof,
}

impl TraceRowOpening {
    fn verify(&self, root: &[u8; 32], hasher: &dyn QuantumHash) -> bool {
        self.proof.verify(root, hasher)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlankQuery {
    pub position: u64,
    pub current: TraceRowOpening,
    pub previous: Option<TraceRowOpening>,
}

#[derive(Debug, Clone)]
struct TraceRow {
    index: u64,
    value: u8,
    running_sum: u64,
}

fn build_trace_rows(polynomial: &BlankPolynomial) -> Vec<TraceRow> {
    let mut rows = Vec::with_capacity(polynomial.len());
    for (idx, &value) in polynomial.values().iter().enumerate() {
        let running_sum = polynomial.running_sum(idx);
        rows.push(TraceRow {
            index: idx as u64,
            value,
            running_sum,
        });
    }
    rows
}

fn serialize_trace_row(row: &TraceRow) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(17);
    bytes.extend_from_slice(&row.index.to_be_bytes());
    bytes.push(row.value);
    bytes.extend_from_slice(&row.running_sum.to_be_bytes());
    bytes
}

fn build_row_opening(
    index: usize,
    trace_rows: &[TraceRow],
    tree: &ChunkedMerkleTree,
) -> TraceRowOpening {
    let row = &trace_rows[index];
    let proof = tree
        .get_proof(index)
        .expect("row proof must exist for valid index");
    TraceRowOpening {
        index: row.index,
        value: row.value,
        running_sum: row.running_sum,
        proof,
    }
}

fn build_query(index: usize, trace_rows: &[TraceRow], tree: &ChunkedMerkleTree) -> BlankQuery {
    let current = build_row_opening(index, trace_rows, tree);
    let previous = if index > 0 {
        Some(build_row_opening(index - 1, trace_rows, tree))
    } else {
        None
    };
    BlankQuery {
        position: current.index,
        current,
        previous,
    }
}

fn debug_stark(msg: &str) {
    if env::var("ZKP_DEBUG_SPOT").is_ok() {
        eprintln!("{}", msg);
    }
}
