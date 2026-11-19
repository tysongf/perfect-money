import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BENCH_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(BENCH_DIR, '..', '..');
const OUT_DIR = path.join(BENCH_DIR, 'public', 'circuits');

const CIRCUITS = ['shield', 'unshield', 'shielded_transfer'];

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const manifestCircuits = [];

  for (const name of CIRCUITS) {
    const artifactSrc = path.join(REPO_ROOT, 'circuits', name, 'target', `${name}.json`);
    const proverTomlSrc = path.join(REPO_ROOT, 'circuits', name, 'Prover.toml');

    if (!fs.existsSync(artifactSrc)) {
      console.error(
        `ERROR: Missing compiled artifact ${artifactSrc}.\n` +
          `Run "bash scripts/prove_and_verify.sh" first to compile circuits.`
      );
      process.exit(1);
    }
    if (!fs.existsSync(proverTomlSrc)) {
      console.error(`ERROR: Missing Prover.toml fixture at ${proverTomlSrc}.`);
      process.exit(1);
    }

    const artifactDst = path.join(OUT_DIR, `${name}.json`);
    const inputsDst = path.join(OUT_DIR, `${name}.inputs.json`);

    fs.copyFileSync(artifactSrc, artifactDst);

    // Parse Prover.toml via Python 3.11 stdlib tomllib; never mutates source Prover.toml.
    const inputsJson = execFileSync(
      'python3',
      [
        '-c',
        'import sys, tomllib, json; print(json.dumps(tomllib.load(open(sys.argv[1], "rb"))))',
        proverTomlSrc,
      ],
      { encoding: 'utf8' }
    );
    const parsedInputs = JSON.parse(inputsJson);
    fs.writeFileSync(inputsDst, JSON.stringify(parsedInputs, null, 2) + '\n');

    const artifactParsed = JSON.parse(fs.readFileSync(artifactDst, 'utf8'));
    const jsonBytes = fs.statSync(artifactDst).size;
    const inputsBytes = fs.statSync(inputsDst).size;

    manifestCircuits.push({
      name,
      json_path: `circuits/${name}.json`,
      inputs_path: `circuits/${name}.inputs.json`,
      noir_version: artifactParsed.noir_version ?? 'unknown',
      abi_params: Array.isArray(artifactParsed.abi?.parameters)
        ? artifactParsed.abi.parameters.length
        : null,
      bytecode_b64_bytes: typeof artifactParsed.bytecode === 'string'
        ? artifactParsed.bytecode.length
        : null,
      json_bytes: jsonBytes,
      inputs_bytes: inputsBytes,
    });
  }

  const manifest = {
    generated_at: new Date().toISOString(),
    circuits: manifestCircuits,
  };
  fs.writeFileSync(
    path.join(OUT_DIR, 'manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n'
  );

  console.log(`Prepared ${manifestCircuits.length} circuit fixtures in ${OUT_DIR}:`);
  for (const c of manifestCircuits) {
    console.log(
      `  - ${c.name}: json=${(c.json_bytes / 1024).toFixed(1)} KiB, ` +
        `bytecode_b64=${c.bytecode_b64_bytes} chars, noir=${c.noir_version}`
    );
  }
}

main();

