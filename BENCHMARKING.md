# Comprehensive Benchmarking Suite

Run the extensive benchmark suite to measure protocol performance:

```powershell
cargo run --release --bin benchmark
```

This will test various configurations by default:
- Node sizes: 10, 16, 32, 64
- Round counts: 5, 10
- Blank strategies: Sampling (2 edges) vs Full Check (all edges)

Override any of these on the command line. For example, to benchmark only a 1000-node instance with both blank strategies:

```bash
cargo run --release --bin benchmark --nodes 1000 --rounds 10 --strategies sampling,full
```

## Metrics Measured

For each configuration, the benchmark tracks:

1. **Timing**
   - Prove time (commitment + all responses)
   - Verify time (full verification pass)

2. **Memory**
   - Peak working set memory during execution

3. **Size**
   - Commitment size (Merkle roots + metadata)
   - Total proof size (all challenge responses)

4. **Protocol Statistics**
   - Number of spot challenges
   - Number of blank challenges
   - Total edges verified across all rounds

## Output

The benchmark produces:

1. **Individual Results** - Detailed metrics for each configuration
2. **Summary Table** - Comparative overview across all tests
3. **Scaling Analysis** - Computational complexity estimates:
   - Time scaling as nodes increase
   - Proof size growth
   - Sampling vs full-check overhead

## Custom Benchmarks

Use the CLI flags to provide comma-separated lists:

```bash
# Mix several graph sizes, add a 1000-node stress pass, and pin rounds
cargo run --release --bin benchmark --nodes 32,64,1000 --rounds 8,12 --strategies sampling
```

## Performance Tips

- Always run with `--release` for accurate timing
- Close other applications to reduce memory noise
- Run multiple times and average for production metrics
- Memory measurements are most accurate on Windows

## Example Output

```
=== ZKP C-Coloring Protocol Benchmark Suite ===

Benchmarking n=64 nodes, 10 rounds, blank strategy: Sampling
  ✓ Prove time:       245.32 ms
  ✓ Verify time:      198.45 ms
  ✓ Memory used:      45.2 MB
  ✓ Commitment size:  0.10 KB
  ✓ Proof size:       156.8 KB
  ✓ Spot challenges:  7
  ✓ Blank challenges: 3
  ✓ Edges verified:   84

=== Scaling Analysis ===

Strategy: Sampling
  Nodes: 8 → 128 (16x increase)
  Prove time scaling:  52.3x
  Verify time scaling: 48.1x
  Proof size scaling:  89.2x
  Estimated prove complexity: O(n^1.42)
  Estimated verify complexity: O(n^1.39)
```
