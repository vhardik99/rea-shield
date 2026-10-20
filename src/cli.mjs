import fs from "node:fs/promises";
import path from "node:path";
import { auditFile } from "./audit.mjs";
import { protectFile } from "./protect.mjs";
import { verifyFiles } from "./verify.mjs";
import { parseArgs, writeJson, readText, parseJson } from "./utils.mjs";

const HELP = `REA-Shield 0.4.0

Usage:
  rea-shield audit <file> [--out report.json]
  rea-shield protect <file> [--out protected.mjs] [--report report.json]
  rea-shield verify <original.mjs> <protected.mjs> --vectors vectors.json [--export default] [--timeout 5000]
  rea-shield benchmark <file> [--vectors vectors.json] [--out report.json]

Options:
  -h, --help     Show help
  --out PATH     Output file
  --report PATH  Transformation report JSON
  --vectors PATH JSON test vectors for verify / benchmark
  --export NAME  Export to verify (default: default)
  --timeout MS   Import timeout warning threshold, 100–30000 ms

Safety:
  Audit scores are heuristic triage signals, not probabilities.
  Transformation is not encryption and cannot hide client-side logic from a determined analyst.
  Verify executes modules with your current OS privileges; use only trusted code.
`;

function statusExit(code) {
  process.exitCode = code;
}

async function commandAudit(positional, options) {
  if (!positional[0]) throw new Error("audit requires a source file.");
  const report = await auditFile(positional[0]);
  if (options.out) await writeJson(options.out, report);
  console.log(JSON.stringify(report, null, 2));
  if (report.parseError) statusExit(3);
}

async function commandProtect(positional, options) {
  if (!positional[0]) throw new Error("protect requires a source file.");
  const output = options.out ?? path.join(path.dirname(path.resolve(positional[0])), `protected_${path.basename(positional[0])}`);
  const report = await protectFile(positional[0], output);
  if (options.report) await writeJson(options.report, report);
  console.log(JSON.stringify(report, null, 2));
}

async function commandVerify(positional, options) {
  if (positional.length < 2 || !options.vectors) throw new Error("verify requires <original> <protected> --vectors <file>.");
  const result = await verifyFiles(positional[0], positional[1], options.vectors, {
    export: options.export ?? "default",
    timeout: options.timeout ?? "5000"
  });
  if (options.out) await writeJson(options.out, result);
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) statusExit(3);
}

async function commandBenchmark(positional, options) {
  if (!positional[0]) throw new Error("benchmark requires a source file.");
  const sourceFile = path.resolve(positional[0]);
  const before = await auditFile(sourceFile);
  const output = path.join(path.dirname(sourceFile), `protected_${path.basename(sourceFile)}`);
  const transform = await protectFile(sourceFile, output);
  const after = await auditFile(output);
  let verification = { status: "skipped", reason: "No --vectors supplied." };
  if (options.vectors) {
    verification = await verifyFiles(sourceFile, output, options.vectors, {
      export: options.export ?? "default",
      timeout: options.timeout ?? "5000"
    });
  }
  const report = {
    version: "0.4.0",
    source: sourceFile,
    protectedOutput: output,
    transformation: transform,
    staticExposureDelta: {
      beforeHeuristicScore: before.heuristicExposureScore ?? null,
      afterHeuristicScore: after.heuristicExposureScore ?? null,
      note: "Score delta is heuristic only and must not be marketed as a security percentage."
    },
    behavioralEquivalence: verification,
    reconstructionResistance: {
      status: "not-measured",
      note: "Requires a separately designed, reproducible attacker benchmark; transformation alone is not evidence."
    }
  };
  if (options.out) await writeJson(options.out, report);
  console.log(JSON.stringify(report, null, 2));
  if (verification.status !== "skipped" && !verification.passed) statusExit(3);
}

export async function runCli(args) {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(HELP);
    return;
  }
  const command = args[0];
  const parsed = parseArgs(args.slice(1));
  if (parsed.options.help) {
    console.log(HELP);
    return;
  }
  switch (command) {
    case "audit": return commandAudit(parsed.positional, parsed.options);
    case "protect": return commandProtect(parsed.positional, parsed.options);
    case "verify": return commandVerify(parsed.positional, parsed.options);
    case "benchmark": return commandBenchmark(parsed.positional, parsed.options);
    default:
      console.error(HELP);
      throw new Error(`Unknown command: ${command}`);
  }
}
