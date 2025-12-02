use crate::graph::{Color, Graph, Spot};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorationSet {
    allowed_spots: HashSet<[u8; 9]>,
    blank_edge_limit: u32,
    graph_size: u32,
}

impl ColorationSet {
    pub fn from_graph(graph: &Graph) -> Self {
        let mut allowed_spots = HashSet::new();
        let blank_edge_limit = graph.blank_count();

        let n = graph.n;
        for a in 0..n {
            for b in (a + 1)..n {
                for c in (b + 1)..n {
                    let spot = graph.get_spot(&[a, b, c]);
                    allowed_spots.insert(Self::spot_to_key(&spot));
                }
            }
        }

        ColorationSet {
            allowed_spots,
            blank_edge_limit,
            graph_size: graph.n,
        }
    }

    fn spot_to_key(spot: &Spot) -> [u8; 9] {
        let permutations = [
            [spot.nodes[0], spot.nodes[1], spot.nodes[2]],
            [spot.nodes[0], spot.nodes[2], spot.nodes[1]],
            [spot.nodes[1], spot.nodes[0], spot.nodes[2]],
            [spot.nodes[1], spot.nodes[2], spot.nodes[0]],
            [spot.nodes[2], spot.nodes[0], spot.nodes[1]],
            [spot.nodes[2], spot.nodes[1], spot.nodes[0]],
        ];

        let mut best = [u8::MAX; 9];
        let mut initialized = false;

        for order in permutations.iter() {
            let mut candidate = [0u8; 9];
            let mut idx = 0;
            for &a in order {
                for &b in order {
                    let color = spot.edges.get(&(a, b)).unwrap_or(&Color::Blank);
                    candidate[idx] = color.to_u8();
                    idx += 1;
                }
            }
            if !initialized || candidate < best {
                best = candidate;
                initialized = true;
            }
        }

        best
    }

    pub fn contains(&self, spot: &Spot) -> bool {
        let key = Self::spot_to_key(spot);
        if !self.allowed_spots.contains(&key) {
            Self::debug_missing(&key);
            return false;
        }
        true
    }

    pub fn blank_limit(&self) -> u32 {
        self.blank_edge_limit
    }

    pub fn graph_size(&self) -> u32 {
        self.graph_size
    }

    pub fn pattern_count(&self) -> usize {
        self.allowed_spots.len()
    }
}

impl ColorationSet {
    fn debug_missing(key: &[u8; 9]) {
        if env::var("ZKP_DEBUG_SPOT").is_ok() {
            eprintln!("missing coloration pattern: {:?}", key);
        }
    }
}
