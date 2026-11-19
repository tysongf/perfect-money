import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BENCH_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(BENCH_DIR, '..', '..');
const REPORT_PATH = path.join(REPO_ROOT, 'target', 'mobile_bench_native.json');

const CIRCUITS = ['shield', 'unshield', 'shielded_transfer'];
const PROFILES = [
  { id: 'native-1t', threads: 1, lowMem: false },
  { id: 'native-2t', threads: 2, lowMem: false },
  { id: 'native-4t', threads: 4, lowMem: false },
  { id: 'native-1t-lowmem', threads: 1, lowMem: true },
];
const WARMUP_ITERS = 1;
const TIMED_ITERS = 5;
const GATE_MS = 2000;

function findBb() {
  if (process.env.BB_BIN && fs.existsSync(process.env.BB_BIN)) {
    return process.env.BB_BIN;
  }
  const homeBb = path.join(os.homedir(), '.bb', 'bb');
  if (fs.existsSync(homeBb)) {
    return homeBb;
  }
  return 'bb';
}

function median(sorted) {
  const n = sorted.length;
  const mid = Math.floor(n / 2);
  return n % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function p95(sorted) {
  const idx = Math.min(sorted.length - 1, Math.ceil(0.95 * sorted.length) - 1);
  return sorted[idx];
}

function parseBbPeakMemMib(output) {
  let maxMib = null;
  for (const m of output.matchAll(/\(mem:\s*([0-9]+(?:\.[0-9]+)?)\s*MiB\)/g)) {
    const val = Number(m[1]);
    if (Number.isFinite(val) && (maxMib === null || val > maxMib)) {
      maxMib = val;
    }
  }
  return maxMib;
}

function runBb(bbBin, args, threads) {
  const env = { ...process.env, HARDWARE_CONCURRENCY: String(threads) };
  const start = performance.now();
  const stdout = execFileSync(bbBin, args, {
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const elapsedMs = performance.now() - start;
  return { elapsedMs, combined: stdout };
}

function main() {
  const bbBin = findBb();
  const bbVersion = execFileSync(bbBin, ['--version'], { encoding: 'utf8' }).trim();
  const cpus = os.cpus();
  const cpuModel = cpus[0]?.model ?? 'unknown';
  const hostCores = cpus.length;

  console.log(`==> Native Mobile-Constrained Benchmark (bb ${bbVersion})`);
  console.log(`    Host CPU: ${cpuModel} (${hostCores} logical cores)`);
  console.log(`    Profiles: ${PROFILES.map((p) => p.id).join(', ')} (${WARMUP_ITERS} warmup + ${TIMED_ITERS} timed runs)`);

  const rows = [];

  for (const name of CIRCUITS) {
    const jsonPath = path.join(REPO_ROOT, 'circuits', name, 'target', `${name}.json`);
    const witnessPath = path.join(REPO_ROOT, 'circuits', name, 'target', 'witness.gz');
    if (!fs.existsSync(jsonPath) || !fs.existsSync(witnessPath)) {
      console.error(
        `ERROR: Missing ${jsonPath} or ${witnessPath}. Run "bash scripts/prove_and_verify.sh" first.`
      );
      process.exit(1);
    }

    const gatesRaw = execFileSync(bbBin, ['gates', '-b', jsonPath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const gatesJson = JSON.parse(gatesRaw);
    const acirOpcodes = gatesJson.functions?.[0]?.acir_opcodes ?? null;
    const circuitSize = gatesJson.functions?.[0]?.circuit_size ?? null;

    for (const profile of PROFILES) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `pm-bench-${name}-`));
      try {
        const vkDir = path.join(tmpDir, 'vk_dir');
        fs.mkdirSync(vkDir, { recursive: true });
        runBb(bbBin, ['write_vk', '-b', jsonPath, '-o', vkDir], profile.threads);
        const vkPath = path.join(vkDir, 'vk');

        const baseProveArgs = [
          'prove',
          '-b',
          jsonPath,
          '-w',
          witnessPath,
          '-k',
          vkPath,
        ];
        if (profile.lowMem) {
          baseProveArgs.push('--slow_low_memory');
        }

        // Warmup runs
        for (let w = 0; w < WARMUP_ITERS; w++) {
          const iterOut = path.join(tmpDir, `warmup_${w}`);
          fs.mkdirSync(iterOut, { recursive: true });
          runBb(bbBin, [...baseProveArgs, '-o', iterOut], profile.threads);
        }

        // Timed runs
        const proveTimes = [];
        let lastOutDir = null;
        for (let i = 0; i < TIMED_ITERS; i++) {
          const iterOut = path.join(tmpDir, `iter_${i}`);
          fs.mkdirSync(iterOut, { recursive: true });
          const { elapsedMs } = runBb(bbBin, [...baseProveArgs, '-o', iterOut], profile.threads);
          proveTimes.push(elapsedMs);
          lastOutDir = iterOut;
        }

        // Verify last proof
        const proofPath = path.join(lastOutDir, 'proof');
        const pubPath = path.join(lastOutDir, 'public_inputs');
        const proofBytes = fs.statSync(proofPath).size;
        const { elapsedMs: verifyMs } = runBb(
          bbBin,
          ['verify', '-p', proofPath, '-k', vkPath, '-i', pubPath],
          profile.threads
        );

        // Separate memory profile pass using python3 resource.getrusage (cross-platform peak RSS)
        const memOutDir = path.join(tmpDir, 'mem_out');
        fs.mkdirSync(memOutDir, { recursive: true });
        const memJsonPath = path.join(tmpDir, 'mem_profile.json');
        let bbStderr = '';
        let maxRssMib = null;
        const env = { ...process.env, HARDWARE_CONCURRENCY: String(profile.threads) };
        const proveMemArgs = [...baseProveArgs, '-o', memOutDir, '--memory_profile_out', memJsonPath];

        const pyWrapper = [
          'import json, resource, subprocess, sys',
          'cmd = sys.argv[1:]',
          'p = subprocess.run(cmd, capture_output=True, text=True)',
          'rss_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss',
          'print(json.dumps({"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "ru_maxrss_kib": rss_kib}))',
        ].join('; ');
        const pyRes = spawnSync('python3', ['-c', pyWrapper, bbBin, ...proveMemArgs], {
          env,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        if (pyRes.status !== 0) {
          throw new Error(`python3 rss wrapper failed: ${pyRes.stderr}`);
        }
        const parsedMem = JSON.parse(pyRes.stdout);
        if (parsedMem.returncode !== 0) {
          throw new Error(`bb memory pass failed: ${parsedMem.stderr}`);
        }
        bbStderr = `${parsedMem.stdout ?? ''}\n${parsedMem.stderr ?? ''}`;
        if (typeof parsedMem.ru_maxrss_kib === 'number' && parsedMem.ru_maxrss_kib > 0) {
          // On macOS ru_maxrss is bytes; on Linux it is KiB.
          const kib = process.platform === 'darwin' ? parsedMem.ru_maxrss_kib / 1024 : parsedMem.ru_maxrss_kib;
          maxRssMib = Number((kib / 1024).toFixed(2));
        }

        let bbReportedPeakMib = parseBbPeakMemMib(bbStderr);
        let memProfileJson = null;
        if (fs.existsSync(memJsonPath)) {
          try {
            memProfileJson = JSON.parse(fs.readFileSync(memJsonPath, 'utf8'));
          } catch {
            memProfileJson = null;
          }
        }

        const sorted = [...proveTimes].sort((a, b) => a - b);
        const minMs = sorted[0];
        const medianMs = median(sorted);
        const p95Ms = p95(sorted);
        const pass2s = medianMs < GATE_MS;

        rows.push({
          circuit: name,
          profile: profile.id,
          threads: profile.threads,
          low_mem: profile.lowMem,
          acir_opcodes: acirOpcodes,
          circuit_gates: circuitSize,
          prove_min_ms: Number(minMs.toFixed(1)),
          prove_median_ms: Number(medianMs.toFixed(1)),
          prove_p95_ms: Number(p95Ms.toFixed(1)),
          prove_all_ms: proveTimes.map((t) => Number(t.toFixed(1))),
          verify_ms: Number(verifyMs.toFixed(1)),
          proof_bytes: proofBytes,
          max_rss_mib: maxRssMib,
          bb_reported_mem_mib: bbReportedPeakMib,
          has_mem_profile_json: memProfileJson !== null,
          pass_2s_gate: pass2s,
        });
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    }
  }

  console.log('');
  console.log(
    [
      'Circuit'.padEnd(18),
      'Profile'.padEnd(17),
      'Gates'.padStart(7),
      'Min(ms)'.padStart(9),
      'Med(ms)'.padStart(9),
      'P95(ms)'.padStart(9),
      'Ver(ms)'.padStart(9),
      'RSS(MiB)'.padStart(10),
      '<2.0s'.padStart(7),
    ].join(' | ')
  );
  console.log('-'.repeat(109));
  for (const r of rows) {
    console.log(
      [
        r.circuit.padEnd(18),
        r.profile.padEnd(17),
        String(r.circuit_gates ?? '-').padStart(7),
        r.prove_min_ms.toFixed(1).padStart(9),
        r.prove_median_ms.toFixed(1).padStart(9),
        r.prove_p95_ms.toFixed(1).padStart(9),
        r.verify_ms.toFixed(1).padStart(9),
        (r.max_rss_mib !== null ? r.max_rss_mib.toFixed(1) : '-').padStart(10),
        (r.pass_2s_gate ? 'PASS' : 'FAIL').padStart(7),
      ].join(' | ')
    );
  }

  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  const report = {
    generated_at: new Date().toISOString(),
    bb_version: bbVersion,
    cpu_model: cpuModel,
    host_logical_cores: hostCores,
    gate_ms: GATE_MS,
    results: rows,
  };
  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');
  console.log(`\nWrote native benchmark report to ${REPORT_PATH}`);
}

main();
