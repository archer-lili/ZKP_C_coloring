use crate::graph::{ColorationSet, Graph};
use crate::protocol::messages::{BlankChallengeResponse, Challenge, Commitments, SpotChallengeResponse};
use crate::utils::random_graph::InstanceParameters;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphInstance {
    pub graph: Graph,
    pub coloration: ColorationSet,
    pub metadata: Option<InstanceParameters>,
}

impl GraphInstance {
    pub fn new(graph: Graph, coloration: ColorationSet) -> Self {
        GraphInstance {
            graph,
            coloration,
            metadata: None,
        }
    }

    pub fn with_metadata(
        graph: Graph,
        coloration: ColorationSet,
        metadata: InstanceParameters,
    ) -> Self {
        GraphInstance {
            graph,
            coloration,
            metadata: Some(metadata),
        }
    }
}

pub fn save_graph_instance<P: AsRef<Path>>(path: P, instance: &GraphInstance) -> io::Result<()> {
    let bytes = bincode::serialize(instance)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("serialize graph: {err}")))?;
    fs::write(path, bytes)
}

pub fn load_graph_instance<P: AsRef<Path>>(path: P) -> io::Result<GraphInstance> {
    let bytes = fs::read(path)?;
    bincode::deserialize(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("deserialize graph: {err}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TranscriptResponse {
    Spot(SpotChallengeResponse),
    Blank(BlankChallengeResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptRound {
    pub challenge: Challenge,
    pub response: TranscriptResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTranscript {
    pub commitments: Commitments,
    pub rounds: Vec<TranscriptRound>,
}

pub fn save_proof<P: AsRef<Path>>(path: P, transcript: &ProofTranscript) -> io::Result<()> {
    let bytes = bincode::serialize(transcript)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("serialize proof: {err}")))?;
    let mut file = fs::File::create(path)?;
    file.write_all(&bytes)
}

pub fn load_proof<P: AsRef<Path>>(path: P) -> io::Result<ProofTranscript> {
    let bytes = fs::read(path)?;
    bincode::deserialize(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("deserialize proof: {err}")))
}
