import { Noir } from '@noir-lang/noir_js';
import { BackendType, Barretenberg, UltraHonkBackend } from '@aztec-foundation/bb.js';

const ALL_CIRCUITS = ['shield', 'unshield', 'shielded_transfer'];
const KNOWN_GATES = {
  shield: 2967,
  unshield: 7525,
  shielded_transfer: 11373,
};
// Matches SrsInitSrs chunk size (2^17 * 32B = 4 MiB compressed BN254 CRS) and covers 11,373 gates.
const SRS_SIZE = 2 ** 17;
const GATE_MS = 2000;

const els = {
  isolated: document.getElementById('tel-isolated'),
  cores: document.getElementById('tel-cores'),
  mem: document.getElementById('tel-mem'),
  ua: document.getElementById('tel-ua'),
  banner: document.getElementById('isolation-banner'),
  threadMode: document.getElementById('thread-mode'),
  iterCount: document.getElementById('iter-count'),
  runAll: document.getElementById('run-all'),
  copyJson: document.getElementById('copy-json'),
  status: document.getElementById('status-line'),
  resultsBody: document.getElementById('results-body'),
  circuitBtns: Array.from(document.querySelectorAll('.circuit-btn')),
};

const resultsMap = new Map();

function median(sorted) {
  const n = sorted.length;
  const mid = Math.floor(n / 2);
  return n % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function getDeviceTelemetry() {
  return {
    userAgent: navigator.userAgent,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemoryGiB: navigator.deviceMemory ?? null,
    crossOriginIsolated: Boolean(window.crossOriginIsolated),
    sharedArrayBufferAvailable: typeof SharedArrayBuffer !== 'undefined',
  };
}

function renderTelemetry() {
  const t = getDeviceTelemetry();
  els.isolated.innerHTML = t.crossOriginIsolated
    ? '<span class="badge badge-pass">true</span>'
    : '<span class="badge badge-warn">false (1-thread fallback)</span>';
  els.cores.textContent = t.hardwareConcurrency ?? 'unknown';
  els.mem.textContent = t.deviceMemoryGiB ? `${t.deviceMemoryGiB} GiB` : 'not exposed';
  els.ua.textContent = t.userAgent;
  els.banner.hidden = t.crossOriginIsolated;
}

function setStatus(msg) {
  els.status.textContent = msg;
}

function setRunning(busy) {
  els.runAll.disabled = busy;
  els.threadMode.disabled = busy;
  els.iterCount.disabled = busy;
  for (const btn of els.circuitBtns) {
    btn.disabled = busy;
  }
  els.copyJson.disabled = busy || resultsMap.size === 0;
}

function renderResults() {
  if (resultsMap.size === 0) {
    return;
  }
  const rowsHtml = [];
  for (const r of resultsMap.values()) {
    const gateBadge = r.pass_2s_gate
      ? '<span class="badge badge-pass">PASS</span>'
      : '<span class="badge badge-fail">FAIL</span>';
    const verifyTxt = r.verified
      ? `${r.verify_ms.toFixed(1)} ms ✓`
      : `${r.verify_ms.toFixed(1)} ms ✗`;
    rowsHtml.push(`
      <tr>
        <td><strong>${r.circuit}</strong> <span style="color:var(--muted)">(${r.gates ?? '?'}g)</span></td>
        <td class="mono">${r.actual_threads} / req ${r.requested_threads}</td>
        <td class="mono">${r.cold_init_ms.toFixed(1)} ms</td>
        <td class="mono">${r.witness_ms.toFixed(1)} ms</td>
        <td class="mono">${r.prove_min_ms.toFixed(1)} ms</td>
        <td class="mono"><strong>${r.prove_median_ms.toFixed(1)} ms</strong></td>
        <td class="mono">${r.prove_max_ms.toFixed(1)} ms</td>
        <td class="mono">${verifyTxt}</td>
        <td class="mono">${r.proof_bytes} B</td>
        <td class="mono"><strong>${r.total_warm_ms.toFixed(1)} ms</strong></td>
        <td>${gateBadge}</td>
      </tr>
    `);
  }
  els.resultsBody.innerHTML = rowsHtml.join('');
}

async function runCircuit(name, requestedThreads, timedIters) {
  setStatus(`[${name}] Fetching compiled circuit and Prover inputs...`);
  const [circuitRes, inputsRes] = await Promise.all([
    fetch(`/circuits/${name}.json`),
    fetch(`/circuits/${name}.inputs.json`),
  ]);
  if (!circuitRes.ok || !inputsRes.ok) {
    throw new Error(`Failed to load /circuits/${name}.{json,inputs.json}`);
  }
  const circuitJson = await circuitRes.json();
  const inputs = await inputsRes.json();

  setStatus(`[${name}] Initializing Barretenberg WasmWorker (${requestedThreads} requested threads)...`);
  const coldStart = performance.now();
  const api = await Barretenberg.new({
    backend: BackendType.WasmWorker,
    threads: requestedThreads,
    srsSize: SRS_SIZE,
  });
  const backend = new UltraHonkBackend(circuitJson.bytecode, api);
  const noir = new Noir(circuitJson);
  await noir.init();
  const coldInitMs = performance.now() - coldStart;

  try {
    setStatus(`[${name}] Warming up Noir witness generation...`);
    await noir.execute(inputs);
    const witnessTimes = [];
    let lastWitness = null;
    for (let i = 0; i < timedIters; i++) {
      const t0 = performance.now();
      const res = await noir.execute(inputs);
      witnessTimes.push(performance.now() - t0);
      lastWitness = res.witness;
    }

    setStatus(`[${name}] Warming up UltraHonk prover...`);
    await backend.generateProof(lastWitness);

    const proveTimes = [];
    let lastProof = null;
    for (let i = 0; i < timedIters; i++) {
      setStatus(`[${name}] Proving iteration ${i + 1}/${timedIters}...`);
      const t0 = performance.now();
      lastProof = await backend.generateProof(lastWitness);
      proveTimes.push(performance.now() - t0);
    }

    setStatus(`[${name}] Verifying proof...`);
    const v0 = performance.now();
    const verified = await backend.verifyProof(lastProof);
    const verifyMs = performance.now() - v0;
    if (verified !== true) {
      throw new Error(`Proof verification returned false for ${name}`);
    }

    const wSorted = [...witnessTimes].sort((a, b) => a - b);
    const pSorted = [...proveTimes].sort((a, b) => a - b);
    const witnessMs = median(wSorted);
    const proveMinMs = pSorted[0];
    const proveMedianMs = median(pSorted);
    const proveMaxMs = pSorted[pSorted.length - 1];
    const totalWarmMs = witnessMs + proveMedianMs;
    const actualThreads = window.crossOriginIsolated
      ? Math.min(requestedThreads, navigator.hardwareConcurrency || 1, 32)
      : 1;

    const result = {
      circuit: name,
      gates: KNOWN_GATES[name] ?? null,
      requested_threads: requestedThreads,
      actual_threads: actualThreads,
      cold_init_ms: Number(coldInitMs.toFixed(1)),
      witness_ms: Number(witnessMs.toFixed(1)),
      prove_min_ms: Number(proveMinMs.toFixed(1)),
      prove_median_ms: Number(proveMedianMs.toFixed(1)),
      prove_max_ms: Number(proveMaxMs.toFixed(1)),
      verify_ms: Number(verifyMs.toFixed(1)),
      proof_bytes: lastProof.proof.length,
      total_warm_ms: Number(totalWarmMs.toFixed(1)),
      verified,
      pass_2s_gate: totalWarmMs < GATE_MS,
    };

    resultsMap.set(`${name}:${actualThreads}t`, result);
    renderResults();
    setStatus(
      `[${name}] Done: witness=${result.witness_ms} ms, prove_med=${result.prove_median_ms} ms, warm_total=${result.total_warm_ms} ms`
    );
  } finally {
    await api.destroy();
  }
}

async function runCircuits(circuits) {
  const mode = els.threadMode.value;
  const timedIters = Number(els.iterCount.value);
  const requestedThreads =
    mode === '1' ? 1 : Math.min(navigator.hardwareConcurrency || 4, 8);

  setRunning(true);
  try {
    for (const c of circuits) {
      await runCircuit(c, requestedThreads, timedIters);
    }
    setStatus(`Completed ${circuits.length} circuit(s). Ready to copy JSON report.`);
  } catch (err) {
    console.error(err);
    setStatus(`ERROR: ${err?.message || String(err)}`);
  } finally {
    setRunning(false);
  }
}

els.runAll.addEventListener('click', () => runCircuits(ALL_CIRCUITS));
for (const btn of els.circuitBtns) {
  btn.addEventListener('click', () => runCircuits([btn.dataset.circuit]));
}

els.copyJson.addEventListener('click', async () => {
  const payload = {
    generated_at: new Date().toISOString(),
    telemetry: getDeviceTelemetry(),
    srs_size: SRS_SIZE,
    gate_ms: GATE_MS,
    results: Array.from(resultsMap.values()),
  };
  await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  setStatus('Copied JSON benchmark report to clipboard.');
});

renderTelemetry();
setRunning(false);

