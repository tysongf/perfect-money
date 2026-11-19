import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const certPath = path.join(__dirname, '.certs', 'cert.pem');
const keyPath = path.join(__dirname, '.certs', 'key.pem');

const useHttps =
  process.env.MOBILE_BENCH_HTTPS === '1' &&
  fs.existsSync(certPath) &&
  fs.existsSync(keyPath);

const httpsConfig = useHttps
  ? {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
    }
  : undefined;

const isolationHeaders = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

export default defineConfig({
  server: {
    host: '0.0.0.0',
    port: 4173,
    strictPort: true,
    https: httpsConfig,
    headers: isolationHeaders,
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    strictPort: true,
    https: httpsConfig,
    headers: isolationHeaders,
  },
  optimizeDeps: {
    exclude: [
      '@noir-lang/acvm_js',
      '@noir-lang/noirc_abi',
      '@aztec-foundation/bb.js',
    ],
  },
  worker: {
    format: 'es',
  },
  build: {
    target: 'esnext',
  },
});

