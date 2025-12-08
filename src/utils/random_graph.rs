use crate::graph::{Color, ColorationSet, Graph};
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};

pub const EDGE_PROBABILITY: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceParameters {
    pub nodes: u32,
    pub edge_probability: f64,
    pub colored_edges: u32,
    pub blank_edges: u32,
}

pub fn generate_hard_instance(n: u32) -> (Graph, ColorationSet, InstanceParameters) {
    let mut graph = Graph::new(n);
    let mut rng = rng();
    let mut colored_edges = 0u32;

    for i in 0..n {
        for j in 0..n {
            if rng.random::<f64>() < EDGE_PROBABILITY {
                let color = random_color(&mut rng);
                graph.overwrite_edge(i, j, color);
                colored_edges += 1;
            } else {
                graph.overwrite_edge(i, j, Color::Blank);
            }
        }
    }

    graph.rebuild_edge_cache();
    let coloration = ColorationSet::from_graph(&graph);
    let blank_edges = graph.blank_count();

    let params = InstanceParameters {
        nodes: n,
        edge_probability: EDGE_PROBABILITY,
        colored_edges,
        blank_edges,
    };

    (graph, coloration, params)
}

pub fn placeholder_random_graph(n: u32) -> (Graph, ColorationSet) {
    let (graph, coloration, _) = generate_hard_instance(n);
    (graph, coloration)
}

fn random_color(rng: &mut impl Rng) -> Color {
    match rng.random_range(0..3) {
        0 => Color::Red,
        1 => Color::Green,
        _ => Color::Yellow,
    }
}
