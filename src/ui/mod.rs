use crate::crypto::merkle::ChunkedMerkleProof;
use crate::graph::{Color, Graph};
use crate::protocol::{
    messages::{BlankChallengeResponse, Commitments, SpotChallengeResponse},
    verifier::VerifierConfig,
};
use crate::stark::prover::StarkParameters;
use crate::utils::serialization::GraphInstance;
use axum::serve;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color as TuiColor, Modifier, Style},
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Context, Line as CanvasLine, Points},
        Block, Borders, Paragraph, Widget,
    },
    Terminal,
};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::f64::consts::PI;
use std::io::{self, Stdout};
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::Duration;
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot};

const LOG_LIMIT: usize = 64;
const WEB_INDEX_HTML: &str = include_str!("web/index.html");

#[derive(Clone, Debug, Serialize)]
pub struct GraphSummary {
    pub nodes: u32,
    pub edges: usize,
    pub blank_edges: u32,
    pub blank_limit: u32,
    pub sample_edges: Vec<String>,
    pub layout: GraphLayout,
    pub color_set_size: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConstraintSummary {
    pub rounds: u32,
    pub spots_per_round: u32,
    pub blank_checks_per_round: u32,
    pub spot_probability: f64,
    pub stark_security: u32,
    pub stark_queries: u32,
    pub stark_chunk: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommitmentSummary {
    pub graph_root: String,
    pub perm_root: String,
    pub blank_root: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RoundSnapshot {
    pub round: Option<u32>,
    pub phase: String,
    pub detail: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VizData {
    pub graph: GraphSummary,
    pub constraints: ConstraintSummary,
    pub commitments: Option<CommitmentSummary>,
    pub round: RoundSnapshot,
    pub logs: VecDeque<String>,
    pub focus: Option<ChallengeFocus>,
    pub merkle: Option<MerkleDisplay>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ChallengeFocus {
    pub title: String,
    pub description: String,
    pub triads: Vec<[u32; 3]>,
    pub edges: Vec<EdgeHighlight>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EdgeHighlight {
    pub from: u32,
    pub to: u32,
    pub color: Color,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct MerkleDisplay {
    pub label: String,
    pub chunk_path: Vec<MerkleStep>,
    pub leaf_path: Vec<MerkleStep>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MerkleStep {
    pub level: usize,
    pub direction: String,
    pub hash: String,
}

pub struct Visualizer {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    data: VizData,
    finished: bool,
}

impl Visualizer {
    pub fn for_instance(
        instance: &GraphInstance,
        verifier: &VerifierConfig,
        stark: &StarkParameters,
    ) -> io::Result<Self> {
        let mut stdout = io::stdout();
        enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let graph_summary = GraphSummary::from_graph(
            &instance.graph,
            instance.coloration.blank_limit(),
            instance.coloration.pattern_count(),
        );
        let constraints = ConstraintSummary::from_configs(verifier, stark);

        Ok(Self {
            terminal,
            data: VizData {
                graph: graph_summary,
                constraints,
                commitments: None,
                round: RoundSnapshot::default(),
                logs: VecDeque::with_capacity(LOG_LIMIT),
                focus: None,
                merkle: None,
            },
            finished: false,
        })
    }

    pub fn set_commitments(&mut self, commitments: &Commitments) -> io::Result<()> {
        self.data.commitments = Some(CommitmentSummary {
            graph_root: hex::encode(commitments.graph_root),
            perm_root: hex::encode(commitments.permutation_root),
            blank_root: hex::encode(commitments.blank_root),
        });
        self.render()
    }

    pub fn update_round(&mut self, snapshot: RoundSnapshot) -> io::Result<()> {
        self.data.round = snapshot;
        self.render()
    }

    pub fn log<S: Into<String>>(&mut self, entry: S) -> io::Result<()> {
        push_log(&mut self.data.logs, entry.into());
        self.render()
    }

    pub fn set_focus(&mut self, focus: Option<ChallengeFocus>) -> io::Result<()> {
        self.data.focus = focus;
        self.render()
    }

    pub fn set_merkle(&mut self, merkle: Option<MerkleDisplay>) -> io::Result<()> {
        self.data.merkle = merkle;
        self.render()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        self.restore_terminal()
    }

    pub fn wait_for_exit(&mut self, prompt: &str) -> io::Result<()> {
        self.log(prompt)?;
        loop {
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                        _ => {}
                    },
                    Event::Resize(_, _) => {
                        self.render()?;
                    }
                    _ => {}
                }
            }
        }
        self.finish()
    }

    fn render(&mut self) -> io::Result<()> {
        let snapshot = self.data.clone();

        self.terminal.draw(|frame| {
            let size = frame.size();
            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(9),
                    Constraint::Length(14),
                    Constraint::Min(7),
                ])
                .split(size);

            let summary_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(34),
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                ])
                .split(vertical[0]);

            let bottom_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6),
                    Constraint::Length(7),
                    Constraint::Min(2),
                ])
                .split(vertical[2]);

            frame.render_widget(Self::graph_block(&snapshot), summary_chunks[0]);
            frame.render_widget(Self::coloration_block(&snapshot), summary_chunks[1]);
            frame.render_widget(Self::constraint_block(&snapshot), summary_chunks[2]);
            frame.render_widget(Self::graph_canvas(&snapshot), vertical[1]);
            frame.render_widget(Self::round_block(&snapshot), bottom_chunks[0]);
            frame.render_widget(Self::challenge_block(&snapshot), bottom_chunks[1]);
            frame.render_widget(Self::log_block(&snapshot), bottom_chunks[2]);
        })?;
        Ok(())
    }

    fn graph_block(data: &VizData) -> Paragraph<'_> {
        let graph = &data.graph;
        let mut lines = Vec::new();
        lines.push(Line::from(format!("nodes: {}", graph.nodes)));
        lines.push(Line::from(format!("edges: {}", graph.edges)));
        lines.push(Line::from(format!("blank edges: {}", graph.blank_edges)));
        lines.push(Line::from(format!(
            "visualized: {}",
            graph.layout.visualized
        )));
        lines.push(Line::from(format!(
            "|C| = {} patterns",
            graph.color_set_size
        )));
        lines.push(Line::from("samples:"));
        for edge in &graph.sample_edges {
            lines.push(Line::from(format!("  {edge}")));
        }
        Paragraph::new(lines).block(Block::default().title("Graph").borders(Borders::ALL))
    }

    fn coloration_block(data: &VizData) -> Paragraph<'_> {
        let mut lines = Vec::new();
        lines.push(Line::from(format!(
            "blank edges: {}",
            data.graph.blank_edges
        )));
        lines.push(Line::from(format!(
            "blank limit: {}",
            data.graph.blank_limit
        )));
        if let Some(commitments) = &data.commitments {
            lines.push(Line::from("commitments:"));
            lines.push(Line::from(short_hash(&commitments.graph_root, "graph")));
            lines.push(Line::from(short_hash(&commitments.perm_root, "perm")));
            lines.push(Line::from(short_hash(&commitments.blank_root, "blank")));
        } else {
            lines.push(Line::from("commitments pending..."));
        }
        Paragraph::new(lines).block(
            Block::default()
                .title("Coloring & commitments")
                .borders(Borders::ALL),
        )
    }

    fn constraint_block(data: &VizData) -> Paragraph<'_> {
        let c = &data.constraints;
        let lines = vec![
            Line::from(format!("rounds: {}", c.rounds)),
            Line::from(format!("spots/round: {}", c.spots_per_round)),
            Line::from(format!("blank checks: {}", c.blank_checks_per_round)),
            Line::from(format!("spot prob: {:.2}", c.spot_probability)),
            Line::from("--- STARK ---"),
            Line::from(format!("security: {} bits", c.stark_security)),
            Line::from(format!("queries: {}", c.stark_queries)),
            Line::from(format!("chunk: {} bytes", c.stark_chunk)),
        ];
        Paragraph::new(lines).block(Block::default().title("Constraints").borders(Borders::ALL))
    }

    fn round_block(data: &VizData) -> Paragraph<'_> {
        let r = &data.round;
        let mut lines = Vec::new();
        if let Some(idx) = r.round {
            lines.push(Line::from(Span::styled(
                format!("Round {}", idx + 1),
                Style::default().add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from("Round pending"));
        }
        if !r.phase.is_empty() {
            lines.push(Line::from(format!("phase: {}", r.phase)));
        }
        if !r.detail.is_empty() {
            lines.push(Line::from(format!("detail: {}", r.detail)));
        }
        if !r.status.is_empty() {
            lines.push(Line::from(format!("status: {}", r.status)));
        }
        Paragraph::new(lines).block(
            Block::default()
                .title("Current round")
                .borders(Borders::ALL),
        )
    }

    fn log_block(data: &VizData) -> Paragraph<'_> {
        let mut lines: Vec<Line> = data
            .logs
            .iter()
            .rev()
            .map(|entry| Line::from(entry.as_str()))
            .collect();
        if lines.is_empty() {
            lines.push(Line::from("logs will appear here"));
        }
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Live log (newest first)")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(TuiColor::Gray))
    }

    fn challenge_block(data: &VizData) -> Paragraph<'_> {
        let mut lines = Vec::new();
        if let Some(focus) = &data.focus {
            lines.push(Line::from(Span::styled(
                focus.title.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(focus.description.clone()));
            if !focus.triads.is_empty() {
                lines.push(Line::from("triads:"));
                for triad in &focus.triads {
                    lines.push(Line::from(format!(
                        "  [{} {} {}]",
                        triad[0], triad[1], triad[2]
                    )));
                }
            }
            if !focus.edges.is_empty() {
                lines.push(Line::from("edges:"));
                for edge in &focus.edges {
                    lines.push(Line::from(format!(
                        "  {}→{} ({:?})",
                        edge.from, edge.to, edge.color
                    )));
                }
            }
            if let Some(merkle) = &data.merkle {
                lines.push(Line::from("merkle focus:"));
                lines.push(Line::from(format!("  {}", merkle.label)));
                lines.push(Line::from(format!(
                    "  leaf depth: {}",
                    merkle.leaf_path.len()
                )));
                lines.push(Line::from(format!(
                    "  chunk depth: {}",
                    merkle.chunk_path.len()
                )));
            }
        } else {
            lines.push(Line::from("challenge focus pending"));
        }
        Paragraph::new(lines).block(
            Block::default()
                .title("Challenge detail")
                .borders(Borders::ALL),
        )
    }

    fn graph_canvas<'a>(data: &'a VizData) -> impl Widget + 'a {
        let layout = data.graph.layout.clone();
        let focus_edges: HashSet<(u32, u32)> = data
            .focus
            .as_ref()
            .map(|focus| {
                focus
                    .edges
                    .iter()
                    .map(|edge| (edge.from, edge.to))
                    .collect()
            })
            .unwrap_or_else(HashSet::new);
        let focus_nodes: HashSet<u32> = data
            .focus
            .as_ref()
            .map(|focus| {
                let mut nodes = HashSet::new();
                for triad in &focus.triads {
                    for node in triad {
                        nodes.insert(*node);
                    }
                }
                nodes
            })
            .unwrap_or_else(HashSet::new);
        let title = format!("Graph view ({} nodes shown)", layout.visualized);
        Canvas::default()
            .block(Block::default().title(title).borders(Borders::ALL))
            .x_bounds([-1.2, 1.2])
            .y_bounds([-1.2, 1.2])
            .paint(move |ctx: &mut Context<'_>| {
                for edge in &layout.edges {
                    let base_line = CanvasLine {
                        x1: edge.x1,
                        y1: edge.y1,
                        x2: edge.x2,
                        y2: edge.y2,
                        color: tui_color(edge.color),
                    };
                    ctx.draw(&base_line);
                    if focus_edges.contains(&(edge.from, edge.to)) {
                        ctx.draw(&CanvasLine {
                            color: TuiColor::White,
                            ..base_line
                        });
                    }
                }

                let mut coords = Vec::with_capacity(layout.nodes.len());
                let mut focus_coords = Vec::new();
                for node in &layout.nodes {
                    coords.push((node.x, node.y));
                    if focus_nodes.contains(&node.idx) {
                        focus_coords.push((node.x, node.y));
                    }
                }
                ctx.draw(&Points {
                    coords: &coords,
                    color: TuiColor::White,
                });
                if !focus_coords.is_empty() {
                    ctx.draw(&Points {
                        coords: &focus_coords,
                        color: TuiColor::Cyan,
                    });
                }

                for node in &layout.nodes {
                    ctx.print(node.x + 0.02, node.y + 0.02, format!("{}", node.idx));
                }
            })
    }

    fn restore_terminal(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Visualizer {
    fn drop(&mut self) {
        let _ = self.restore_terminal();
    }
}

pub struct WebVisualizer {
    data: Arc<RwLock<VizData>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_thread: Option<thread::JoinHandle<()>>,
    address: SocketAddr,
    finished: bool,
}

impl WebVisualizer {
    pub fn for_instance(
        instance: &GraphInstance,
        verifier: &VerifierConfig,
        stark: &StarkParameters,
        port: u16,
    ) -> io::Result<Self> {
        let graph_summary = GraphSummary::from_graph(
            &instance.graph,
            instance.coloration.blank_limit(),
            instance.coloration.pattern_count(),
        );
        let constraints = ConstraintSummary::from_configs(verifier, stark);
        let data = VizData {
            graph: graph_summary,
            constraints,
            commitments: None,
            round: RoundSnapshot::default(),
            logs: VecDeque::with_capacity(LOG_LIMIT),
            focus: None,
            merkle: None,
        };

        let shared = Arc::new(RwLock::new(data));
        let (server_thread, shutdown_tx, address) = spawn_web_server(shared.clone(), port)?;

        Ok(Self {
            data: shared,
            shutdown_tx: Some(shutdown_tx),
            server_thread: Some(server_thread),
            address,
            finished: false,
        })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn set_commitments(&self, commitments: &Commitments) -> io::Result<()> {
        self.modify_data(|data| {
            data.commitments = Some(CommitmentSummary {
                graph_root: hex::encode(&commitments.graph_root),
                perm_root: hex::encode(&commitments.permutation_root),
                blank_root: hex::encode(&commitments.blank_root),
            });
        })
    }

    pub fn update_round(&self, snapshot: RoundSnapshot) -> io::Result<()> {
        self.modify_data(|data| {
            data.round = snapshot;
        })
    }

    pub fn log<S: Into<String>>(&self, entry: S) -> io::Result<()> {
        self.modify_data(|data| {
            push_log(&mut data.logs, entry.into());
        })
    }

    pub fn set_focus(&self, focus: Option<ChallengeFocus>) -> io::Result<()> {
        self.modify_data(|data| {
            data.focus = focus;
        })
    }

    pub fn set_merkle(&self, merkle: Option<MerkleDisplay>) -> io::Result<()> {
        self.modify_data(|data| {
            data.merkle = merkle;
        })
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.shutdown_server();
        self.finished = true;
        Ok(())
    }

    pub fn wait_for_exit(&mut self, prompt: &str) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        println!("{prompt}");
        println!(
            "Open {} in your browser to inspect the run.",
            self.base_url()
        );
        println!("Press Enter once you're done to shut down the server.");
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        self.finish()
    }

    fn modify_data<F>(&self, mutator: F) -> io::Result<()>
    where
        F: FnOnce(&mut VizData),
    {
        let mut guard = self
            .data
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "web visualizer state poisoned"))?;
        mutator(&mut guard);
        Ok(())
    }

    fn shutdown_server(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WebVisualizer {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[derive(Clone)]
struct WebAppState {
    data: Arc<RwLock<VizData>>,
}

fn spawn_web_server(
    state: Arc<RwLock<VizData>>,
    port: u16,
) -> io::Result<(thread::JoinHandle<()>, oneshot::Sender<()>, SocketAddr)> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle = thread::spawn(move || {
        let runtime = Runtime::new().expect("failed to start tokio runtime for web viz");
        let app_state = WebAppState { data: state };
        runtime.block_on(async move {
            let app = Router::new()
                .route("/", get(index_handler))
                .route("/snapshot", get(snapshot_handler))
                .with_state(app_state);

            let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
            let listener = TcpListener::bind(bind_addr)
                .await
                .expect("failed to bind web visualizer port");
            let addr = listener.local_addr().expect("web listener addr");
            let _ = ready_tx.send(addr);

            let server = serve(listener, app);
            let shutdown = async move {
                let _ = shutdown_rx.await;
            };

            if let Err(err) = server.with_graceful_shutdown(shutdown).await {
                eprintln!("web visualizer server exited with error: {err}");
            }
        });
    });

    let address = ready_rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "web visualizer failed to start"))?;

    Ok((handle, shutdown_tx, address))
}

async fn index_handler() -> impl IntoResponse {
    Html(WEB_INDEX_HTML)
}

async fn snapshot_handler(State(state): State<WebAppState>) -> impl IntoResponse {
    let snapshot = {
        let guard = state.data.read().expect("web visualization state poisoned");
        guard.clone()
    };
    Json(snapshot)
}

impl GraphSummary {
    pub fn from_graph(graph: &Graph, blank_limit: u32, color_set_size: usize) -> Self {
        let nodes = graph.n;
        let edges = (graph.n as usize) * (graph.n as usize);
        let blank_edges = graph.blank_count();
        let mut sample_edges = Vec::new();
        let mut added = 0;
        for i in 0..graph.n {
            for j in 0..graph.n {
                if i == j {
                    continue;
                }
                let color = graph.get_edge(i, j);
                if color == Color::Blank {
                    continue;
                }
                sample_edges.push(format!("{}→{}:{}", i, j, color_symbol(color)));
                added += 1;
                if added >= 5 {
                    break;
                }
            }
            if added >= 5 {
                break;
            }
        }
        if sample_edges.is_empty() {
            sample_edges.push("(no colored edges sampled)".to_string());
        }
        GraphSummary {
            nodes,
            edges,
            blank_edges,
            blank_limit,
            sample_edges,
            layout: GraphLayout::build(graph),
            color_set_size,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphLayout {
    pub nodes: Vec<NodePoint>,
    pub edges: Vec<EdgeSegment>,
    pub visualized: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodePoint {
    pub idx: u32,
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EdgeSegment {
    pub from: u32,
    pub to: u32,
    pub x1: f64,
    pub y1: f64,
    pub x2: f64,
    pub y2: f64,
    pub color: Color,
}

impl GraphLayout {
    const MAX_NODES: u32 = u32::MAX;
    const MAX_EDGES: usize = 96;

    fn build(graph: &Graph) -> Self {
        let visualized = graph.n.min(Self::MAX_NODES).max(1);
        let mut nodes = Vec::with_capacity(visualized as usize);
        for idx in 0..visualized {
            let angle = 2.0 * PI * (idx as f64) / (visualized as f64);
            let x = angle.cos();
            let y = angle.sin();
            nodes.push(NodePoint { idx, x, y });
        }

        let mut edges = Vec::new();
        'outer: for from in 0..visualized {
            for to in 0..visualized {
                if from == to {
                    continue;
                }
                let color = graph.get_edge(from, to);
                if color == Color::Blank {
                    continue;
                }
                let src = &nodes[from as usize];
                let dst = &nodes[to as usize];
                edges.push(EdgeSegment {
                    from,
                    to,
                    x1: src.x,
                    y1: src.y,
                    x2: dst.x,
                    y2: dst.y,
                    color,
                });
                if edges.len() >= Self::MAX_EDGES {
                    break 'outer;
                }
            }
        }

        GraphLayout {
            nodes,
            edges,
            visualized,
        }
    }
}
impl ConstraintSummary {
    pub fn from_configs(verifier: &VerifierConfig, stark: &StarkParameters) -> Self {
        ConstraintSummary {
            rounds: verifier.rounds,
            spots_per_round: verifier.spots_per_round,
            blank_checks_per_round: verifier.blank_checks_per_round,
            spot_probability: verifier.spot_probability,
            stark_security: stark.security_level,
            stark_queries: stark.num_queries,
            stark_chunk: stark.chunk_size,
        }
    }
}

fn short_hash(hex_string: &str, label: &str) -> String {
    if hex_string.len() <= 12 {
        format!("{label}: {hex_string}")
    } else {
        format!(
            "{label}: {}…{}",
            &hex_string[..6],
            &hex_string[hex_string.len() - 4..]
        )
    }
}

fn color_symbol(color: Color) -> char {
    match color {
        Color::Red => 'R',
        Color::Green => 'G',
        Color::Yellow => 'Y',
        Color::Blank => '_',
    }
}

fn tui_color(color: Color) -> TuiColor {
    match color {
        Color::Red => TuiColor::Red,
        Color::Green => TuiColor::Green,
        Color::Yellow => TuiColor::Yellow,
        Color::Blank => TuiColor::Gray,
    }
}

fn push_log(logs: &mut VecDeque<String>, entry: String) {
    if logs.len() == LOG_LIMIT {
        logs.pop_front();
    }
    logs.push_back(entry);
}

pub fn focus_from_spot_response(
    challenge_label: &str,
    spots: &[[u32; 3]],
    response: &SpotChallengeResponse,
) -> ChallengeFocus {
    let triads = spots.to_vec();
    let mut edges = Vec::new();
    for witness in &response.responses {
        for edge in &witness.edges {
            edges.push(EdgeHighlight {
                from: edge.from,
                to: edge.to,
                color: edge.color,
            });
        }
    }
    ChallengeFocus {
        title: format!("Spot challenge {challenge_label}"),
        description: format!("{} triads verified", triads.len()),
        triads,
        edges,
    }
}

pub fn focus_from_blank_response(
    challenge_label: &str,
    edge_indices: &[u64],
    response: &BlankChallengeResponse,
) -> ChallengeFocus {
    let mut edges = Vec::new();
    for opening in &response.edges {
        edges.push(EdgeHighlight {
            from: opening.from,
            to: opening.to,
            color: opening.color,
        });
    }
    ChallengeFocus {
        title: format!("Blank challenge {challenge_label}"),
        description: format!("{} edges probed", edge_indices.len()),
        triads: Vec::new(),
        edges,
    }
}

pub fn merkle_display_from_chunked(label: &str, proof: &ChunkedMerkleProof) -> MerkleDisplay {
    MerkleDisplay {
        label: label.to_string(),
        leaf_path: steps_from_merkle_proof(&proof.leaf_proof),
        chunk_path: steps_from_merkle_proof(&proof.chunk_proof),
    }
}

fn steps_from_merkle_proof(proof: &crate::crypto::merkle::MerkleProof) -> Vec<MerkleStep> {
    let mut steps = Vec::with_capacity(proof.path.len() + 1);
    steps.push(MerkleStep {
        level: 0,
        direction: "leaf".to_string(),
        hash: hex::encode(proof.leaf_hash),
    });
    for (level, (sibling, is_right)) in proof.path.iter().enumerate() {
        steps.push(MerkleStep {
            level: level + 1,
            direction: if *is_right {
                "sibling-right".to_string()
            } else {
                "sibling-left".to_string()
            },
            hash: hex::encode(sibling),
        });
    }
    steps
}
