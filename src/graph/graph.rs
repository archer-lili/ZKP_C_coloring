use crate::crypto::hash::QuantumHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Color {
    Red,
    Green,
    Yellow,
    Blank,
}

impl Color {
    pub fn to_u8(self) -> u8 {
        match self {
            Color::Red => 0,
            Color::Green => 1,
            Color::Yellow => 2,
            Color::Blank => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Color::Red),
            1 => Some(Color::Green),
            2 => Some(Color::Yellow),
            3 => Some(Color::Blank),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: u32,
    pub to: u32,
    pub color: Color,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    pub n: u32,
    pub edges: Vec<Edge>,
    pub adjacency: Vec<Vec<Color>>,
}

impl Graph {
    pub fn new(n: u32) -> Self {
        Graph {
            n,
            edges: Vec::new(),
            adjacency: vec![vec![Color::Blank; n as usize]; n as usize],
        }
    }

    pub fn set_edge(&mut self, from: u32, to: u32, color: Color) {
        self.adjacency[from as usize][to as usize] = color;
        self.edges.push(Edge { from, to, color });
    }

    pub fn overwrite_edge(&mut self, from: u32, to: u32, color: Color) {
        self.adjacency[from as usize][to as usize] = color;
    }

    pub fn rebuild_edge_cache(&mut self) {
        self.edges.clear();
        for i in 0..self.n {
            for j in 0..self.n {
                let color = self.adjacency[i as usize][j as usize];
                self.edges.push(Edge { from: i, to: j, color });
            }
        }
    }

    pub fn get_edge(&self, from: u32, to: u32) -> Color {
        self.adjacency[from as usize][to as usize]
    }

    pub fn blank_count(&self) -> u32 {
        self.adjacency
            .iter()
            .map(|row| row.iter().filter(|&&color| color == Color::Blank).count() as u32)
            .sum()
    }

    pub fn apply_permutation(&self, permutation: &[u32]) -> Self {
        assert_eq!(permutation.len() as u32, self.n);
        let mut permuted = Graph::new(self.n);

        for i in 0..self.n {
            for j in 0..self.n {
                let src_i = permutation[i as usize];
                let src_j = permutation[j as usize];
                let color = self.get_edge(src_i, src_j);
                permuted.set_edge(i, j, color);
            }
        }

        permuted
    }

    pub fn get_spot(&self, nodes: &[u32; 3]) -> Spot {
        let mut edges = HashMap::new();
        for &a in nodes {
            for &b in nodes {
                let color = self.get_edge(a, b);
                edges.insert((a, b), color);
            }
        }

        Spot {
            nodes: *nodes,
            edges,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spot {
    pub nodes: [u32; 3],
    pub edges: HashMap<(u32, u32), Color>,
}

impl Spot {
    pub fn is_valid(&self, coloration_set: &crate::graph::coloring::ColorationSet) -> bool {
        coloration_set.contains(self)
    }

    pub fn hash(&self, hasher: &dyn QuantumHash) -> [u8; 32] {
        let mut data = Vec::new();
        for &node in &self.nodes {
            data.extend_from_slice(&node.to_be_bytes());
        }

        let mut entries: Vec<_> = self.edges.iter().collect();
        entries.sort_by_key(|(&(a, b), _)| (a, b));

        for ((a, b), color) in entries {
            data.extend_from_slice(&a.to_be_bytes());
            data.extend_from_slice(&b.to_be_bytes());
            data.push(color.to_u8());
        }

        hasher.hash(&data)
    }
}
