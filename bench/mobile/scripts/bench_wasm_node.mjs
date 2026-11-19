import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { Noir } from '@noir-lang/noir_js';
import { BackendType, Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BENCH_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(BENCH_DIR, '..', '..');
const FIXTURES_DIR = path.join(BENCH_DIR, 'public', 'circuits');
const REPORT_PATH = path.join(REPO_ROOT, 'target', 'mobile_bench_wasm_node.json');

const CIRCUITS = ['shield', 'unshield', 'shielded_transfer'];
const THREAD_MODES = [1, 4];
const WARMUP_ITERS = 1;
const TIMED_ITERS = 3;
// Max circuit is shielded_transfer (11,373 gates). SrsInitSrs requires compressed CRS chunks
// of 4,194,304 bytes (2^17 = 131,072 points).
const SRS_SIZE = 2 ** 17;
const GATE_MS = 2000;

function median(sorted) {
  const n = sorted.length;
  const mid = Math.floor(n / 2);
  return n % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

async function benchProfile(circuitName, threads) {
  const jsonPath = path.join(FIXTURES_DIR, `${circuitName}.json`);
  const inputsPath = path.join(FIXTURES_DIR, `${circuitName}.inputs.json`);
  if (!fs.existsSync(jsonPath) || !fs.existsSync(inputsPath)) {
    throw new Error(
      `Missing fixture files for ${circuitName} in ${FIXTURES_DIR}. Run "npm run fixtures" first.`
    );
  }

  const circuitJson = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const inputs = JSON.parse(fs.readFileSync(inputsPath, 'utf8'));

  const wasmLogs = [];
  const coldStart = performance.now();
  // Explicitly force BackendType.Wasm so bb.js never silently delegates to NativeUnixSocket.
  const api = await Barretenberg.new({
    backend: BackendType.Wasm,
    threads,
    srsSize: SRS_SIZE,
    logger: (msg) => wasmLogs.push(msg),
  });
  const backend = new UltraHonkBackend(circuitJson.bytecode, api);
  const noir = new Noir(circuitJson);
  await noir.init();
  const coldInitMs = performance.now() - coldStart;

  try {
    const resolvedBackend = api.options?.backend ?? 'unknown';
    if (resolvedBackend !== BackendType.Wasm) {
      throw new Error(`Expected BackendType.Wasm, got ${resolvedBackend}`);
    }

    // Witness generation: 1 warmup + 3 timed runs
    await noir.execute(inputs);
    const witnessTimes = [];
    let lastWitness = null;
    for (let i = 0; i < TIMED_ITERS; i++) {
      const t0 = performance.now();
      const res = await noir.execute(inputs);
      witnessTimes.push(performance.now() - t0);
      lastWitness = res.witness;
    }

    // Proof generation: 1 warmup + 3 timed runs
    for (let w = 0; w < WARMUP_ITERS; w++) {
      await backend.generateProof(lastWitness);
    }
    const proveTimes = [];
    let lastProof = null;
    for (let i = 0; i < TIMED_ITERS; i++) {
      const t0 = performance.now();
      lastProof = await backend.generateProof(lastWitness);
      proveTimes.push(performance.now() - t0);
    }

    // Proof verification (assert true)
    const v0 = performance.now();
    const verified = await backend.verifyProof(lastProof);
    const verifyMs = performance.now() - v0;
    if (verified !== true) {
      throw new Error(`WASM proof verification FAILED for ${circuitName} (${threads}t)`);
    }

    const wSorted = [...witnessTimes].sort((a, b) => a - b);
    const pSorted = [...proveTimes].sort((a, b) => a - b);
    const witnessMs = median(wSorted);
    const proveMinMs = pSorted[0];
    const proveMedianMs = median(pSorted);
    const proveMaxMs = pSorted[pSorted.length - 1];
    const totalWarmMs = witnessMs + proveMedianMs;
    const rssMib = process.memoryUsage().rss / (1024 * 1024);

    // Extract actual initialized thread line logged by BarretenbergWasmMain if present
    const initLine = wasmLogs.find((l) => l.includes('Initializing bb wasm')) ?? null;

    return {
      circuit: circuitName,
      backend: resolvedBackend,
      threads,
      srs_size: SRS_SIZE,
      init_detail: initLine,
      cold_init_ms: Number(coldInitMs.toFixed(1)),
      witness_ms: Number(witnessMs.toFixed(1)),
      prove_min_ms: Number(proveMinMs.toFixed(1)),
      prove_median_ms: Number(proveMedianMs.toFixed(1)),
      prove_max_ms: Number(proveMaxMs.toFixed(1)),
      verify_ms: Number(verifyMs.toFixed(1)),
      proof_bytes: lastProof.proof.length,
      total_warm_ms: Number(totalWarmMs.toFixed(1)),
      rss_mib: Number(rssMib.toFixed(1)),
      verified,
      pass_2s_gate: totalWarmMs < GATE_MS,
    };
  } finally {
    await api.destroy();
  }
}

async function main() {
  const cpus = os.cpus();
  console.log('==> Headless Node.js Pure-WASM Benchmark (@noir-lang/noir_js@1.0.0 + @aztec-foundation/bb.js@6.0.0)');
  console.log(`    Host CPU: ${cpus[0]?.model ?? 'unknown'} (${cpus.length} logical cores)`);
  console.log(`    Backend forced: BackendType.Wasm (threads: ${THREAD_MODES.join(', ')}, srsSize: ${SRS_SIZE})`);
  console.log(`    Note: Cold init downloads/reads CRS on first run and caches uncompressed in ~/.bb-crs`);

  const rows = [];
  for (const name of CIRCUITS) {
    for (const threads of THREAD_MODES) {
      const r = await benchProfile(name, threads);
      rows.push(r);
    }
  }

  console.log('');
  console.log(
    [
      'Circuit'.padEnd(18),
      'Backend'.padEnd(6),
      'Thr'.padStart(3),
      'Init(ms)'.padStart(9),
      'Wit(ms)'.padStart(8),
      'PrvMin'.padStart(8),
      'PrvMed'.padStart(8),
      'PrvMax'.padStart(8),
      'Ver(ms)'.padStart(8),
      'WarmTot'.padStart(8),
      'RSS(MiB)'.padStart(9),
      '<2.0s'.padStart(6),
    ].join(' | ')
  );
  console.log('-'.repeat(124));
  for (const r of rows) {
    console.log(
      [
        r.circuit.padEnd(18),
        r.backend.padEnd(6),
        String(r.threads).padStart(3),
        r.cold_init_ms.toFixed(1).padStart(9),
        r.witness_ms.toFixed(1).padStart(8),
        r.prove_min_ms.toFixed(1).padStart(8),
        r.prove_median_ms.toFixed(1).padStart(8),
        r.prove_max_ms.toFixed(1).padStart(8),
        r.verify_ms.toFixed(1).padStart(8),
        r.total_warm_ms.toFixed(1).padStart(8),
        r.rss_mib.toFixed(1).padStart(9),
        (r.pass_2s_gate ? 'PASS' : 'FAIL').padStart(6),
      ].join(' | ')
    );
  }

  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  const report = {
    generated_at: new Date().toISOString(),
    node_version: process.version,
    cpu_model: cpus[0]?.model ?? 'unknown',
    host_logical_cores: cpus.length,
    forced_backend: BackendType.Wasm,
    srs_size: SRS_SIZE,
    gate_ms: GATE_MS,
    results: rows,
  };
  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');
  console.log(`\nWrote Node WASM benchmark report to ${REPORT_PATH}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
