import { pathToFileURL } from "node:url";
import path from "node:path";
import { parseJson, finiteNumber } from "./utils.mjs";

function resolveExport(moduleNamespace, exportName) {
  if (exportName && exportName !== "default") return moduleNamespace[exportName];
  return moduleNamespace.default ?? moduleNamespace;
}

function equalValue(a, b, tolerance) {
  if (typeof a === "number" && typeof b === "number") {
    if (!Number.isFinite(a) || !Number.isFinite(b)) return Object.is(a, b);
    return Math.abs(a - b) <= tolerance.absolute + tolerance.relative * Math.max(Math.abs(a), Math.abs(b));
  }
  if (Object.is(a, b)) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, i) => equalValue(value, b[i], tolerance));
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();
    return ak.length === bk.length && ak.every((key, i) => key === bk[i] && equalValue(a[key], b[key], tolerance));
  }
  return false;
}

export async function verifyFiles(originalFile, protectedFile, vectorsFile, options = {}) {
  const timeoutMs = Math.max(100, Math.min(Number(options.timeout ?? 5000), 30000));
  const originalUrl = pathToFileURL(path.resolve(originalFile)).href;
  const protectedUrl = pathToFileURL(path.resolve(protectedFile)).href;
  const vectorText = await (await import("node:fs/promises")).readFile(vectorsFile, "utf8");
  const vectors = parseJson(vectorText, vectorsFile);
  if (!Array.isArray(vectors) || vectors.length === 0) throw new Error("Vector file must be a non-empty JSON array.");
  const worker = new WorkerlessVerifier(originalUrl, protectedUrl, vectors, timeoutMs, options);
  return worker.run();
}

class WorkerlessVerifier {
  constructor(originalUrl, protectedUrl, vectors, timeoutMs, options) {
    this.originalUrl = originalUrl;
    this.protectedUrl = protectedUrl;
    this.vectors = vectors;
    this.timeoutMs = timeoutMs;
    this.options = options;
  }

  async run() {
    const tolerance = {
      absolute: Number(this.options.absTolerance ?? 1e-9),
      relative: Number(this.options.relTolerance ?? 1e-9)
    };
    if (![tolerance.absolute, tolerance.relative].every((x) => Number.isFinite(x) && x >= 0)) {
      throw new Error("Tolerances must be finite non-negative numbers.");
    }
    const imports = Promise.all([import(this.originalUrl), import(this.protectedUrl)]);
    let originalModule, protectedModule;
    try {
      [originalModule, protectedModule] = await Promise.race([
        imports,
        new Promise((_, reject) => setTimeout(() => reject(new Error(`Module import exceeded ${this.timeoutMs} ms (timeout does not stop module execution).`)), this.timeoutMs))
      ]);
    } catch (error) {
      return { passed: false, reason: "module-import-failed-or-timed-out", error: error.message, checked: 0 };
    }
    const exportName = this.options.export ?? "default";
    const originalFn = resolveExport(originalModule, exportName);
    const protectedFn = resolveExport(protectedModule, exportName);
    if (typeof originalFn !== "function" || typeof protectedFn !== "function") {
      return { passed: false, reason: "export-not-function", export: exportName, checked: 0 };
    }
    const failures = [];
    for (let index = 0; index < this.vectors.length; index += 1) {
      const vector = this.vectors[index];
      if (!vector || !Array.isArray(vector.args)) {
        failures.push({ index, reason: "Each vector must contain an args array." });
        continue;
      }
      try {
        const [a, b] = await Promise.all([
          Promise.resolve().then(() => originalFn(...vector.args)),
          Promise.resolve().then(() => protectedFn(...vector.args))
        ]);
        if (!equalValue(a, b, tolerance)) failures.push({ index, args: vector.args, original: a, protected: b, reason: "output-mismatch" });
        if (Object.hasOwn(vector, "expected") && !equalValue(a, vector.expected, tolerance)) failures.push({ index, args: vector.args, original: a, expected: vector.expected, reason: "expected-mismatch" });
      } catch (error) {
        failures.push({ index, args: vector.args, reason: "execution-error", error: error.message });
      }
    }
    return {
      passed: failures.length === 0,
      checked: this.vectors.length,
      failures,
      tolerance,
      limitation: "Finite test vectors do not prove universal equivalence. Modules execute with the current user's OS privileges; only run trusted test artifacts."
    };
  }
}
