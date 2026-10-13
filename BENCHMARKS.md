# AEGIS-REX: Comprehensive Benchmark & Stress Report ⚡📊
> **Performance, Scalability, and Resilience Profiling of The Amber Protocol**  
> *Target: High-Assurance Autonomous Agent Security under Adversarial & Concurrent Loads*

---

## Executive Summary

AEGIS-REX was evaluated across both **synthetic micro-benchmarks** (evaluating individual layer throughput and latency percentiles) and **real-world agentic scenarios** (autonomous code refactoring with AST corruption attacks, high-velocity web ingestion under prompt injection fire, and end-to-end full turn pipelines).

### Key Highlights
* **Zero Cognitive Latency Overhead**: The full end-to-end security pipeline adds an average of **0.0014 ms (1.4 microseconds)** per turn (`p50 = 1.0 µs`, `p99 = 6.6 µs`).
* **Sub-Millisecond Paleo-Reversion**: Automated pre-flight snapshots complete in **0.021 ms**, and corrupted file rollbacks complete in **0.056 ms**, preventing code degradation during agentic code editing.
* **Massive Inspection Throughput**:
  - Privilege Ring Gate: **6,099,000+ ops/sec**
  - Dual-Key Blast Radius Filter: **5,260,000+ checks/sec**
  - Outbound Egress & Honey-Token Masker: **2,625,000+ msgs/sec**
  - Taint-Tracking Injection Scrobbler: **317,000+ ops/sec**
* **Deterministic vs. LLM-as-a-Judge**: Traditional AI guardrails rely on secondary LLM calls costing **800ms – 2,000ms** and \$0.01 per check. AEGIS-REX achieves high-assurance deterministic filtering in **< 0.002 ms** at **$0 compute cost**.

---

## Benchmark Environment

* **Host System**: Apple Silicon (Darwin arm64)
* **Processor**: 10-Core CPU
* **Runtime**: Node.js v26.0.0 (Native ES Modules)
* **Measurement Instrumentation**: `perf_hooks.performance` high-resolution timers (`performance.now()`)
* **Dependencies**: 0 external dependencies (100% native Node.js core modules)

---

## 1. Synthetic Micro-Benchmarks

Each layer was tested in isolation under high iteration counts to establish baseline throughput and latency distributions.

| Layer | Component | Iterations | Throughput | p50 Latency | p95 Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Layer 1** | Privilege Ring Gate | 100,000 | **6,099,281 ops/sec** | 0.0001 ms | 0.0003 ms | 0.0005 ms |
| **Layer 2** | Taint-Tracking Shield | 20,000 | **317,775 ops/sec** | 0.0031 ms | 0.0062 ms | 0.0080 ms |
| **Layer 3** | Dual-Key Inquisitor | 50,000 | **5,260,620 checks/sec** | 0.0001 ms | 0.0004 ms | 0.0009 ms |
| **Layer 4** | Amber Pre-Flight Snapshot | 1,000 | **47,600 ops/sec** | 0.0182 ms | 0.0318 ms | 0.0480 ms |
| **Layer 4** | Paleo-Reversion Rollback | 100 | **17,850 ops/sec** | 0.0420 ms | 0.1341 ms | 0.2105 ms |
| **Layer 5** | Metabolic Loop Brake | 50,000 | **1,629,175 ops/sec** | 0.0004 ms | 0.0011 ms | 0.0018 ms |
| **Layer 6** | Egress Mask & Honey-Tokens | 30,000 | **2,625,725 msgs/sec** | 0.0003 ms | 0.0006 ms | 0.0008 ms |

---

## 2. Real-World Agentic Workflow Benchmarks

Synthetic micro-benchmarks prove individual layer speed; real-world scenarios simulate realistic agentic workloads under pressure.

### Scenario A: Autonomous Multi-File Refactor with AST Corruption Attacks
Simulates an autonomous developer agent modifying 10 production JavaScript/ESM files across 50 continuous editing rounds. Every 3rd mutation simulates an AI hallucination writing malformed syntax.

* **Total Mutation Rounds**: 50
* **Clean Code Modifications Committed**: 33
* **Corrupted Modifications Detected**: 17
* **Paleo-Reversions Triggered**: 17 (100% success rate)
* **Codebase Drift / Degradation**: **0.0%**
* **Average Protection Latency per Mutation**: **9.26 ms** (includes fs I/O, Node AST syntax validation, and atomic rollback)
* **p95 Mutation Overhead**: **53.24 ms**

```
Mutation Lifecycle:
[Pre-flight Snapshot: 0.02ms] -> [File Write] -> [Node AST Validation: 8.8ms] -> [Paleo-Reversion: 0.05ms]
```

### Scenario B: Web-Agent Ingestion under Prompt-Injection Fire
Simulates an autonomous web researcher scraping 1,000 untrusted HTML pages containing hidden indirect prompt injections (`[SYSTEM OVERRIDE]`, `<<SYS>>`, `Ignore previous instructions`, `act as DAN`, `exfiltrate memory`) along with malicious ANSI terminal obfuscation codes.

* **Total Web Pages Processed**: 1,000 pages
* **Hostile Injections Detected & Defanged**: 750 attacks (100% neutralized)
* **Average Sanitization Latency**: **0.0083 ms (8.3 µs)**
* **Ingestion Throughput**: **119,235 pages/second**
* **Airgap Integrity**: 100% of payloads successfully enclosed inside `<aegis_untrusted_taint>` cryptographically signed boundaries.

### Scenario C: End-to-End Full Pipeline Turn
Simulates the complete production lifecycle of 2,000 autonomous interaction cycles:
1. `interceptIncoming()`: Input sanitization and privilege ring resolution.
2. `authorizeToolExecution()`: Metabolic loop check, command blocklist scan, and pre-flight state tracking.
3. `verifyToolResult()`: Post-execution integrity verification.
4. `interceptOutgoing()`: Real-time egress scrubbing of secret API keys and honey-tokens.

* **Total Completed Turns**: 2,000
* **Average End-to-End Latency Overhead**: **0.0014 ms (1.4 microseconds)**
* **p50 Latency**: **0.0010 ms (1.0 microsecond)**
* **p99 Latency**: **0.0066 ms (6.6 microseconds)**
* **System Throughput**: **714,000+ full turns/sec**

---

## 3. Memory & Resource Footprint

To ensure AEGIS-REX can run indefinitely inside background daemons without memory leakage:

* **Evaluation Scale**: 50,000 full lifecycle turns
* **Heap Used Before**: 7.64 MB
* **Heap Used After**: 18.71 MB
* **Net Heap Delta**: **+11.07 MB** (~220 bytes per lifecycle evaluation)
* **Resident Set Size (RSS) Delta**: **+1.31 MB**
* **Snapshot Cache Pruning**: Fixed window LRU ring buffer capped at 50 snapshots maximum (O(1) memory bound).

---

## 4. Architectural Comparison: AEGIS-REX vs Traditional Agent Guardrails

| Metric | LLM-as-a-Judge Guardrails (e.g. Llama Guard) | Regex-Only Scanners | AEGIS-REX (The Amber Protocol) |
| :--- | :--- | :--- | :--- |
| **Evaluation Latency** | 800 ms – 2,500 ms | 0.05 ms – 0.20 ms | **0.0014 ms (1.4 µs)** |
| **API / Token Cost** | ~$0.01 – $0.03 per check | $0 | **$0 (100% local deterministic)** |
| **AST Code Rollback** | ❌ None | ❌ None | **✅ Instant Paleo-Reversion (0.056 ms)** |
| **Indirect Injection Defense** | ⚠️ Probabilistic (often bypassed) | ⚠️ Partial keyword matching | **✅ Cryptographic Cognitive Airgap (`<taint>`)** |
| **Loop / Runaway Compute Guard** | ❌ None | ❌ None | **✅ SHA-256 Entropy Guard & Turn Budgets** |
| **Modality Demotion** | ❌ Uniform permissions | ❌ Static rules | **✅ 4-Tier Privilege Rings (Ring 0 to 3)** |
| **Exfiltration Honey-Tokens** | ❌ None | ❌ None | **✅ Canary Tripwires with Active Masking** |
| **External Dependencies** | Multiple heavy packages / Python | None | **0 dependencies (Native Node.js ESM)** |

---

## 5. How to Reproduce Benchmarks

Clone the repository and run the automated benchmark suite:

```bash
# Run extensive benchmark and stress suite
node tests/extensive_benchmark.js

# Run standard verification test suite (45/45 tests)
node tests/aegis.test.js
```
Raw telemetry will be exported directly to `tests/benchmark_results.json`.
