use crate::graph::{Color, ColorationSet, Graph};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceParameters {
    pub nodes: u32,
    pub tournament_size: u32,
    pub grid_rows: u32,
    pub grid_cols: u32,
    pub blank_budget: u32,
}

pub fn generate_hard_instance(n: u32) -> (Graph, ColorationSet, InstanceParameters) {
    let params = derive_parameters(n);
    let mut graph = Graph::new(n);
    initialize_dense_edges(&mut graph);
    embed_tournament(&mut graph, params.tournament_size);
    embed_grid(
        &mut graph,
        params.tournament_size,
        params.grid_rows,
        params.grid_cols,
    );
    encode_node_codes(&mut graph, params.tournament_size);

    let mut blank_budget = BlankBudget::new(params.blank_budget);
    plant_tournament_blanks(&mut graph, params.tournament_size, &mut blank_budget);
    plant_grid_blanks(
        &mut graph,
        params.tournament_size,
        params.grid_rows,
        params.grid_cols,
        &mut blank_budget,
    );
    blank_budget.finalize(&mut graph);

    graph.rebuild_edge_cache();
    let coloration = ColorationSet::from_graph(&graph);
    (graph, coloration, params)
}

pub fn placeholder_random_graph(n: u32) -> (Graph, ColorationSet) {
    let (graph, coloration, _) = generate_hard_instance(n);
    (graph, coloration)
}

fn derive_parameters(n: u32) -> InstanceParameters {
    let p = ((n as f64 / 2.0).sqrt().round() as u32).max(2);
    let mut grid_rows = 2 * p;
    let mut grid_cols = p;
    let mut tournament_size = ((5.0 * (p as f64).powi(2)).ln() / 1.5f64.ln()).floor() as u32;
    if tournament_size == 0 {
        tournament_size = 1;
    }

    while tournament_size + grid_rows * grid_cols > n && grid_cols > 1 {
        grid_cols -= 1;
    }
    while tournament_size + grid_rows * grid_cols > n && grid_rows > 2 {
        grid_rows -= 1;
    }
    let blank_budget = (tournament_size + 4 * grid_cols * grid_rows).min(n.saturating_mul(n));

    InstanceParameters {
        nodes: n,
        tournament_size,
        grid_rows,
        grid_cols,
        blank_budget,
    }
}

fn initialize_dense_edges(graph: &mut Graph) {
    for i in 0..graph.n {
        for j in 0..graph.n {
            let color = if i == j { Color::Red } else { Color::Red };
            graph.overwrite_edge(i, j, color);
        }
    }
}

fn embed_tournament(graph: &mut Graph, k: u32) {
    for a in 0..k {
        for b in 0..k {
            if a == b {
                continue;
            }
            let color = if a < b { Color::Green } else { Color::Yellow };
            graph.overwrite_edge(a, b, color);
        }
    }
}

fn embed_grid(graph: &mut Graph, offset: u32, rows: u32, cols: u32) {
    if rows == 0 || cols == 0 {
        return;
    }
    for r in 0..rows {
        for c in 0..cols {
            let node = offset + r * cols + c;
            if node >= graph.n {
                continue;
            }
            let right = offset + r * cols + ((c + 1) % cols);
            let down = offset + ((r + 1) % rows) * cols + c;
            if right < graph.n {
                graph.overwrite_edge(node, right, Color::Yellow);
            }
            if down < graph.n {
                graph.overwrite_edge(node, down, Color::Green);
            }
        }
    }
}

fn encode_node_codes(graph: &mut Graph, tournament_size: u32) {
    if tournament_size == 0 {
        return;
    }
    for (idx, node) in ((tournament_size)..graph.n).enumerate() {
        for bit in 0..tournament_size {
            let pattern = ((idx as u32) >> (bit % 16)) & 1;
            let color = if pattern == 1 {
                Color::Red
            } else {
                Color::Green
            };
            graph.overwrite_edge(node, bit, color);
            graph.overwrite_edge(bit, node, color);
        }
    }
}

fn plant_tournament_blanks(graph: &mut Graph, k: u32, budget: &mut BlankBudget) {
    for i in 0..k {
        let target = (i + 1) % graph.n.max(1);
        budget.mark(graph, i, target);
    }
}

fn plant_grid_blanks(
    graph: &mut Graph,
    offset: u32,
    rows: u32,
    cols: u32,
    budget: &mut BlankBudget,
) {
    if rows == 0 || cols == 0 {
        return;
    }
    for r in 0..rows {
        for c in 0..cols {
            let node = offset + r * cols + c;
            if node >= graph.n {
                continue;
            }
            let right = offset + r * cols + ((c + 1) % cols);
            let down = offset + ((r + 1) % rows) * cols + c;
            if right < graph.n {
                budget.mark(graph, node, right);
            }
            if down < graph.n {
                budget.mark(graph, node, down);
            }
        }
    }
}

struct BlankBudget {
    target: u32,
    count: u32,
}

impl BlankBudget {
    fn new(target: u32) -> Self {
        BlankBudget { target, count: 0 }
    }

    fn mark(&mut self, graph: &mut Graph, from: u32, to: u32) {
        if self.count >= self.target {
            return;
        }
        if graph.get_edge(from, to) != Color::Blank {
            graph.overwrite_edge(from, to, Color::Blank);
            self.count += 1;
        }
    }

    fn finalize(&mut self, graph: &mut Graph) {
        if self.count >= self.target {
            return;
        }
        let mut rng = rand::rng();
        while self.count < self.target {
            let from = rng.random_range(0..graph.n);
            let to = rng.random_range(0..graph.n);
            if graph.get_edge(from, to) != Color::Blank {
                graph.overwrite_edge(from, to, Color::Blank);
                self.count += 1;
            }
        }
    }
}
