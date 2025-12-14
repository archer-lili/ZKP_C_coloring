# ZKP C-Coloring Protocol Benchmarking Guide

## Quick Start

### CLI Benchmark (Simple)
Test a specific configuration quickly:
```bash
cargo run --release -- benchmark --nodes 32 --rounds 10 --samples 3 --blank-sampling
```

Need the 1000-node stress test? Override the nodes list:
```bash
cargo run --release --bin benchmark --nodes 1000 --rounds 10 --strategies sampling,full
```

### Comprehensive Benchmark Suite
Test multiple configurations automatically:
```bash
cargo run --release --bin benchmark
```

## Benchmark Metrics

### Measured Parameters

1. **Timing**
   - **Prove Time**: Total time to generate commitment + all challenge responses
   - **Verify Time**: Total time to verify all rounds

2. **Memory Usage**
   - Peak working set memory during protocol execution (Windows only)

3. **Size**
   - **Commitment Size**: Merkle roots (graph, permutation, blank) + metadata
   - **Proof Size**: Sum of all challenge responses across rounds

4. **Protocol Statistics**
   - Spot challenges issued
   - Blank challenges issued
   - Total edges verified

### Configuration Options

#### Node Counts
- Small graphs: 8-16 nodes (fast, visualization-friendly)
- Medium graphs: 32-64 nodes (balanced performance)
- Large graphs: 100-128 nodes (stress testing)
- Massive graphs: 256-1000+ nodes (use the `--nodes` flag to target them explicitly)

#### Blank Checking Strategies

**Sampling** (`--blank-sampling`):
- Checks 2 random blank edges per blank challenge
- Higher spot probability (0.7)
- Smaller proofs, faster verification
- Use for: Production deployments with many nodes

**Full Check**:
- Checks ALL edges (n²) per blank challenge
- Lower spot probability (0.3)
- Larger proofs, thorough validation
- Use for: Maximum security audits, small graphs

#### Custom Parameters

```bash
cargo run --release -- benchmark \
  --nodes 64 \
  --rounds 15 \
  --samples 5 \
  --spots-per-round 6 \
  --blank-checks-per-round 4 \
  --blank-sampling
```

## Understanding Results

### Example Output

```
Benchmarking n=64 nodes, 10 rounds, blank strategy: Sampling
  ✓ Prove time:       245.32 ms
  ✓ Verify time:      198.45 ms
  ✓ Memory used:      45.2 MB
  ✓ Commitment size:  0.10 KB
  ✓ Proof size:       156.8 KB
  ✓ Spot challenges:  7
  ✓ Blank challenges: 3
  ✓ Edges verified:   84
```

### Scaling Analysis

The comprehensive benchmark computes:
- **Time Scaling**: How prove/verify time grows with node count
- **Complexity Estimate**: Empirical O(n^k) calculation
- **Strategy Comparison**: Sampling vs full check overhead

Example:
```
Nodes: 10 → 64 (6.4x increase)
Prove time scaling:  18.2x
Estimated prove complexity: O(n^1.68)
```

### Interpreting Complexity

- **O(n^1.0)**: Linear scaling (ideal)
- **O(n^1.5)**: Better than quadratic (acceptable)
- **O(n^2.0)**: Quadratic (expected for graph operations)
- **O(n^3.0)**: Cubic (avoid for large graphs)

## Performance Optimization Tips

### For Faster Proving
1. Use `--blank-sampling` for graphs > 32 nodes
2. Reduce `--spots-per-round` if acceptable for security model
3. Lower `--rounds` count (minimum 5-8 for soundness)

### For Smaller Proofs
1. Enable sampling strategy
2. Reduce spots per round
3. Use probabilistic blank checking

### For Maximum Security
1. Use full blank checking on critical deployments
2. Increase rounds (20+)
3. Increase spots per round (6-8)

## Typical Performance (Release Build)

| Nodes | Rounds | Strategy | Prove (ms) | Verify (ms) | Proof (KB) |
|-------|--------|----------|------------|-------------|------------|
| 10    | 10     | Sampling | 0.8        | 0.3         | 12         |
| 32    | 10     | Sampling | 8.5        | 6.2         | 68         |
| 64    | 10     | Sampling | 245        | 198         | 157        |
| 64    | 10     | Full     | 890        | 762         | 1,240      |

*Note: Actual performance varies by CPU, memory, and system load*

## Memory Profiling

Memory tracking is automatic on Windows. For Unix systems, consider:
```bash
/usr/bin/time -v cargo run --release --bin benchmark
```

## Continuous Integration

For CI/CD pipelines, use lightweight configurations:
```bash
cargo run --release -- benchmark --nodes 16 --rounds 5 --samples 1 --blank-sampling
```

## Advanced Analysis

### Custom Test Matrix

Pass comma-separated lists to the CLI flags instead of editing code:
```bash
cargo run --release --bin benchmark --nodes 20,40,80,1000 --rounds 5,10,15 --strategies sampling
```

### Export Results

Redirect output to file for analysis:
```bash
cargo run --release --bin benchmark > benchmark_results.txt
```

### Compare Strategies

Run both strategies and compare:
```bash
cargo run --release -- benchmark --nodes 32 --rounds 10 --samples 5 --blank-sampling > sampling.txt
cargo run --release -- benchmark --nodes 32 --rounds 10 --samples 5 > fullcheck.txt
```

## Troubleshooting

**High memory usage**:
- Reduce node count or rounds
- Check for memory leaks with valgrind/drmemory

**Slow compilation**:
- Use `--release` only for final benchmarks
- Dev builds are 10-100x slower

**Inconsistent results**:
- Close other applications
- Run multiple samples (--samples 5+)
- Check CPU throttling/thermal limits

## Questions & Support

See README.md for protocol details and BENCHMARKING.md for implementation notes.
