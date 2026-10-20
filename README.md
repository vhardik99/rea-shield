# REA-Shield

Cross-platform **JavaScript/TypeScript source audit and constrained transformation toolkit**. Runs anywhere a supported Node.js runtime is available, including Windows, macOS, Linux, and most cloud VMs/containers. This package is not a universal binary protector and does not directly execute on iOS/Android without a compatible Node.js environment or a server-side deployment.

## What it does

- Scans source for patterns that may indicate embedded credentials.
- Reports basic function and branching-complexity metrics.
- Transforms a deliberately small, annotated subset of arithmetic functions into a simple stack interpreter.
- Runs differential test vectors against original and transformed modules.
- Produces separate reports for transformation coverage, behavior checks, heuristic static exposure signals, and reconstruction-resistance status.

## Important limitations

- **Not encryption.** A determined analyst can inspect client-side code and runtime behavior. Keep high-value secrets, authorization decisions, and proprietary pricing/risk logic on a server you control.
- The exposure score is a transparent heuristic, not a probability of theft or a security rating.
- A finite set of test vectors cannot prove universal behavioral equivalence.
- `verify` imports and executes both modules in the current process with the current user's OS permissions. Only run trusted test artifacts. The timeout is not a sandbox and cannot reliably stop blocked or hostile module code.
- This release supports a limited JavaScript AST transformation. It does not claim to protect arbitrary code, native binaries, mobile apps, or cloud workloads automatically.
- Do not use deceptive prompt-injection payloads or malicious decoys. If adding decoys, keep them inert, labeled, and safe.

## Requirements

- Node.js `>=20.19.0`
- npm
- Internet access during initial dependency installation

## Install from source

```bash
git clone https://github.com/vhardik99/rea-shield.git
cd rea-shield
npm ci
npm test
```

If you prefer not to use a global link, run `node bin/rea-shield.mjs --help`.

## Quick start

Mark a supported named function with `@rea-protect`:

```js
// @rea-protect
export function calculatePrice(base, rate, quantity) {
  return (base * rate + base) * quantity;
}

export default calculatePrice;
```

Audit:

```bash
node bin/rea-shield.mjs audit fixtures/sample.js --out .tmp/audit.json
```

Protect:

```bash
node bin/rea-shield.mjs protect fixtures/sample.js --out .tmp/protected_sample.mjs --report .tmp/protect-report.json
```

Verify with vectors:

```bash
node bin/rea-shield.mjs verify fixtures/sample.js .tmp/protected_sample.mjs \
  --vectors fixtures/sample.vectors.json --export default
```

Benchmark:

```bash
node bin/rea-shield.mjs benchmark fixtures/sample.js \
  --vectors fixtures/sample.vectors.json --out .tmp/benchmark.json
```

On PowerShell, put a command on one line if line-continuation syntax differs.

## Test vector format

A JSON array. Each item must have an `args` array; `expected` is optional.

```json
[
  { "args": [100, 0.18, 2], "expected": 236 },
  { "args": [49.99, 0.05, 3], "expected": 157.4685 }
]
```

The verifier compares original and protected output using configurable absolute and relative numeric tolerances internally. Keep vectors representative of boundary cases, invalid input, and real production behavior. The current arithmetic transformer only supports numeric literals, simple parameters, unary minus, and `+ - * /`.

## Platform strategy

| Target | Recommended execution mode | Notes |
|---|---|---|
| Windows / macOS / Linux | Node.js CLI | Primary supported mode |
| Docker / Kubernetes | Node.js container | Add OS-level restrictions if running untrusted code |
| AWS / Google Cloud / Azure | CI job, VM, container, or serverless job | Package itself is cloud-agnostic; deployment and IAM are your responsibility |
| Android / iOS | Run the tool in CI/cloud or a compatible Node.js environment | This is not a native mobile app or an iOS/Android SDK |
| Browser | Build-time/server-side audit only | Node.js CLI dependencies are not designed for direct browser execution |

Cross-platform means the source tool can run on supported Node.js hosts; it does **not** mean a single zip automatically installs itself or gains access to every cloud/mobile platform.

## Security deployment guidance

- Keep secrets out of source; use your cloud provider's secret manager or environment-level secret injection.
- Never run the verifier against untrusted source in a privileged environment.
- For untrusted test code, use a disposable container or VM with no secrets, a read-only filesystem where possible, network disabled by default, CPU/memory/process limits, and a non-root user. A child process alone is not isolation.
- For production IP protection, move critical logic server-side and expose a narrow authenticated API.
- Treat audit findings as triage requiring human review; pattern matching can miss secrets and can produce false positives.

## CI

A GitHub Actions workflow tests Node.js 20, 22, and 24. The lockfile should be generated and committed with `npm install --package-lock-only` followed by `npm ci` before release. CI does not certify the product as secure.

## License

MIT. See `LICENSE`.
