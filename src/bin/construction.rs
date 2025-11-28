use rand::prelude::*;
use rand::thread_rng;
use std::collections::HashSet;

// --------------------------------------------
// COLOR ENCODING
// --------------------------------------------
// 'a' = ABSENT edge
// 'b' = BLANK (real edge, blanked)
// r/g/y/p = colored real edges
pub type EdgeColoring = Vec<Vec<char>>;

pub const ABSENT: char = 'a';
pub const BLANK:  char = 'b';


// -------------------------------------------------------------
// Directed graph structure
// -------------------------------------------------------------
#[derive(Clone)]
pub struct DiGraph {
    pub n: usize,
    pub adj: Vec<Vec<bool>>,       // adjacency matrix
    pub adj_list: Vec<Vec<usize>>, // adjacency list
}

// -------------------------------------------------------------
// Generate random directed graph
// -------------------------------------------------------------
pub fn random_digraph(n: usize, p: f64) -> DiGraph {
    let mut rng = thread_rng();
    let mut adj = vec![vec![false; n]; n];

    for i in 0..n {
        for j in 0..n {
            if i != j {
                adj[i][j] = rng.gen::<f64>() < p;
            }
        }
    }

    // adjacency list
    let mut adj_list = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..n {
            if adj[i][j] {
                adj_list[i].push(j);
            }
        }
    }

    DiGraph { n, adj, adj_list }
}

// -------------------------------------------------------------
// Color edges with exactly l blank edges (others colored)
// -------------------------------------------------------------
pub fn random_edge_coloring_with_blanks(
    G: &DiGraph,
    k: usize,
    l: usize
) -> EdgeColoring
{
    let mut rng = thread_rng();
    let n = G.n;

    // palette of colors
    let palette = ['r','g','y'];
    assert!(k <= palette.len());

    // initialize all as ABSENT
    let mut colors = vec![vec![ABSENT; n]; n];

    // collect real edges
    let mut edges = Vec::new();
    for i in 0..n {
        for j in 0..n {
            if G.adj[i][j] {
                edges.push((i, j));
            }
        }
    }

    // first: color every real edge with some color
    for &(i, j) in &edges {
        colors[i][j] = palette[rng.gen_range(0..k)];
    }

    // now make exactly l of them blank
    edges.shuffle(&mut rng);
    let l_actual = l.min(edges.len());

    for &(i, j) in edges.iter().take(l_actual) {
        colors[i][j] = BLANK;
    }

    colors
}

// -------------------------------------------------------------
// Triad: 3-node induced subgraph
// -------------------------------------------------------------
#[derive(Clone)]
pub struct Triad {
    pub edges: [bool; 9],
    pub colors: [char; 9],
}

// Extract triad (a,b,c)
pub fn extract_triad(G: &DiGraph, c: &EdgeColoring, a: usize, b: usize, d: usize) -> Triad {
    let verts = [a, b, d];
    let mut edges = [false; 9];
    let mut colors = [ABSENT; 9];

    for (i, &vi) in verts.iter().enumerate() {
        for (j, &vj) in verts.iter().enumerate() {
            let idx = i * 3 + j;
            edges[idx] = G.adj[vi][vj];
            colors[idx] = c[vi][vj];
        }
    }

    Triad { edges, colors }
}

// -------------------------------------------------------------
// Canonical triad under isomorphism
// -------------------------------------------------------------
pub fn canonical_triad(t: &Triad) -> ([bool; 9], [char; 9]) {
    let perms = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let mut best: Option<([bool; 9], [char; 9])> = None;

    for p in perms {
        let mut e2 = [false; 9];
        let mut c2 = [ABSENT; 9];

        for i in 0..3 {
            for j in 0..3 {
                let idx = i * 3 + j;
                e2[idx] = t.edges[p[i] * 3 + p[j]];
                c2[idx] = t.colors[p[i] * 3 + p[j]];
            }
        }

        let cand = (e2, c2);
        if best.is_none() || cand < best.clone().unwrap() {
            best = Some(cand);
        }
    }

    best.unwrap()
}

// -------------------------------------------------------------
// Build C'
// -------------------------------------------------------------
pub fn build_C_prime(
    G: &DiGraph,
    colors: &EdgeColoring,
) -> HashSet<([bool; 9], [char; 9])>
{
    let mut set = HashSet::new();

    for a in 0..G.n {
        for b in (a + 1)..G.n {
            for c in (b + 1)..G.n {
                let triad = extract_triad(G, colors, a, b, c);
                set.insert(canonical_triad(&triad));
            }
        }
    }

    set
}

// -------------------------------------------------------------
// Pretty print triads
// -------------------------------------------------------------
pub fn print_c_prime(C_prime: &HashSet<([bool; 9], [char; 9])>) {
    let mut idx = 0;
    for (edges, colors) in C_prime.iter() {
        println!("=== Triad {} ===", idx);
        idx += 1;

        for i in 0..3 {
            print!("  {} → [", i);
            let mut first = true;

            for j in 0..3 {
                if edges[i*3 + j] {
                    if !first { print!(", "); }
                    let col = colors[i*3 + j];
                    print!("({} {})", j, col);
                    first = false;
                }
            }

            println!("]");
        }

        println!();
    }
}

// -------------------------------------------------------------
// FULL CONSTRUCTION
// -------------------------------------------------------------
pub fn construct_for_zk(
    n: usize,
    k: usize,
    p: f64,
) -> (
    HashSet<([bool; 9], [char; 9])>,
    DiGraph,
    usize,
    EdgeColoring
) {
    let G = random_digraph(n, p);

    // count real edges
    let real_edges: Vec<(usize, usize)> = (0..n)
        .flat_map(|i| (0..n).map(move |j| (i,j)))
        .filter(|&(i,j)| G.adj[i][j])
        .collect();

    let num_real = real_edges.len();

    let mut rng = thread_rng();
    let l = rng.gen_range(0..=num_real);  // correct global blanks

    let edge_colors = random_edge_coloring_with_blanks(&G, k, l);
    let C_prime = build_C_prime(&G, &edge_colors);

    (C_prime, G, l, edge_colors)
}

// -------------------------------------------------------------
// MAIN
// -------------------------------------------------------------
fn main() {
    let n = 8;
    let k = 3;
    let p = 0.4;

    let (C_prime, G, l, edge_colors) =
        construct_for_zk(n, k, p);

    println!("ℓ blanks = {}", l);
    println!("Graph adjacency list: {:?}", G.adj_list);

    println!("Edge colors:");
    for row in &edge_colors {
        println!("{:?}", row);
    }

    println!("C′ size = {}", C_prime.len());

    println!("\n--- TRIADS ---\n");
    print_c_prime(&C_prime);
}
