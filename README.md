# zkp_c_coloring

Quantum-resistant zero-knowledge proofs for directed graph coloration. The prover commits to a permuted graph, answers spot and blank challenges backed by Merkle trees, and proves the blank budget with a STARK-style argument. The verifier deterministically derives challenges from the commitments and replayable transcripts.

## What is already implemented?
- Hard-instance graph generator that embeds a tournament, toroidal grid, and encoded node IDs with a tunable blank budget (not done)(`src/utils/random_graph.rs`).
- Permutation-invariant spot checking plus chunked Merkle commitments for edges, permutation vectors, and blank bits.
- Blank-count STARK proof (constraints, FRI sampling, proof/verification) with Blake3 hashing.
- Full CLI (`cargo run -- <command>`) supporting graph generation, transcript creation, transcript verification, and benchmarking.
- Integration test suite covering normal protocol flow plus feature-gated 64/100/128-node stress cases.
- Legacy `construction` binary for experimenting with the historical triad/color set workflow.

## Repository layout
| Path | Purpose |
|------|---------|
| `src/crypto` | Hashing, Merkle tree implementations, polynomial helpers, and public re-exports. |
| `src/graph` | Graph storage, coloration set derivation, tournament helpers. |
| `src/protocol` | Messages, prover/verifier state machines, transcript logic. |
| `src/stark` | Blank-count constraints, FRI sampling, and proof generation/verification. |
| `src/utils` | Random graph generator, permutations, serialization glue. |
| `src/bin/construction.rs` | Legacy pipeline that builds the historic `C'` triad set. |
| `tests/protocol_flow.rs` | Fast end-to-end transcript tests (always run). |
| `tests/protocol_stress.rs` | Large-node scenarios gated by the `stress-tests` feature and `#[ignore]`. |
| `target/` | Cargo build artifacts (generated). |

## Running the CLI
All commands assume a recent stable Rust toolchain.

```bash
cargo run -- --help
```

### Generate a graph instance
```bash
cargo run -- generate --nodes 64 --output instances/graph64.bin
```
Writes a serialized `GraphInstance` (graph + coloration + metadata) that every other command consumes.

### Produce a proof transcript
```bash
cargo run -- prove --instance instances/graph64.bin --proof proofs/graph64.transcript --rounds 12
```
Runs the full commit/challenge/response loop locally and stores the transcript.

### Verify a stored transcript
```bash
cargo run -- verify --instance instances/graph64.bin --proof proofs/graph64.transcript
```
Deterministically replays each round against the commitments.

### Benchmark proving and verification
```bash
cargo run -- benchmark --nodes 64 --rounds 12 --samples 5
```
Generates fresh graphs per sample and reports average prove/verify timings.

## Live visualization UI

Track every commitment, challenge, and response in a dedicated terminal dashboard powered by `ratatui`:

```bash
cargo run -- visualize --instance instances/graph64.bin --rounds 10
```

The UI shows:
- Graph structure summary (node count, blank edges, sampled colored edges).
- Live force-circle drawing of the committed graph (colored edges plus node labels) so you can see permutations taking effect in real time.
- Coloring and commitment roots (graph/permutation/blank trees).
- Verifier and STARK constraints (round count, spot probability, chunk size, etc.).
- A continuously refreshing log that calls out every spot and blank validation as it happens.

The dashboard stays onscreen until you press `q` (or `Esc`), so you have time to inspect the final state.

Because the visualizer drives the real prover/verifier code, what you see is the actual protocol execution—no mock data or shortcuts.

### Web dashboard

If you want smoother edges and a richer layout, spin up the browser-based dashboard:

```bash
cargo run --bin zkp_c_coloring -- visualize-web --instance instances/graph10.bin --rounds 10 --port 8787
```

The CLI hosts a local Axum server (default `127.0.0.1:8787`) that serves a fully animated canvas view, challenge focus panel, and Merkle-path navigator. Leave the terminal running, open the printed URL in your browser, and press Enter in the terminal when you are ready to shut it down.

> **Note:** The UI now focuses on clarity over scale and only accepts graph instances with ≤10 nodes. Re-run `cargo run -- generate --nodes 10` (or smaller) before launching the visualizers.

The dashboard highlights:

- Pulsing edges/nodes for every spot or blank challenge, color-coded by edge assignment.
- Live statistics for the coloration constraint set `C` (|C| matches the number of admissible triads embedded in the instance).
- A Merkle viewer that walks the chunked proof path (leaf and chunk trees animate step-by-step).
- Streaming logs, commitments, and STARK parameters synchronized with the prover/verifier state machine.

## Tests

- **Fast suite:** `cargo test` (runs `tests/protocol_flow.rs` and unit tests).
- **Stress suite:**
	```bash
	cargo test --features stress-tests -- --ignored
	```
	Executes the 64-, 100-, and 128-node round-trip scenarios defined in `tests/protocol_stress.rs`. Each test remains `#[ignore]` by default so you must pass `-- --ignored` even when the feature flag is enabled.
- **Target a single stress case:**
	```bash
	cargo test --features stress-tests -- --ignored protocol_round_trip_accepts_specific_coloring_c_on_100_nodes
	```

## Where to add or modify graph generation logic

1. **Primary entry point:** `src/utils/random_graph.rs::generate_hard_instance` currently derives tournament/grid sizes, seeds blanks, and returns both the `Graph` and its permutation-invariant `ColorationSet`. Extend or replace this function to change the default graph family used by the CLI and tests.
2. **Parameter tuning:** Adjust `derive_parameters` in the same file to influence tournament size, grid dimensions, and blank budgets for larger/smaller graphs.
3. **Custom generators:** If you want parallel implementations (e.g., precise hard-instance constructions), add a new module under `src/utils/` and switch the CLI/test callers (`generate_hard_instance` usage sites) to select between generators via flags.
4. **Legacy workflow:** `src/bin/construction.rs` still mirrors the original `C'` triad-set construction pipeline. Use it as a reference for porting alternative color-set logic or for validating canonical triads.

After modifying generation logic, re-run both the fast and stress suites to ensure the prover and verifier remain in sync.

## Legacy construction binary

```bash
cargo run --bin construction
```
Prints the randomly colored digraph, blank edge budget, and the canonicalized triad set `C'`. This is useful when comparing against the historical description from the original C-coloring zero-knowledge guide.

## Next steps

- Implement the missing “precise hard-instance generator” once the exact graph description from the guide is available.
- Expand `VerifierConfig` CLI options (spots per round, blank checks per round) if you need different soundness/efficiency trade-offs.
- Package the CLI as a reusable library crate once the APIs stabilize.