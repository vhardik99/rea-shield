import test from "node:test";
import assert from "node:assert/strict";
import { auditSource } from "../src/audit.mjs";
import { protectSource } from "../src/protect.mjs";

test("audit reports a possible hard-coded token", () => {
  const report = auditSource('const api_key = "12345678901234567890";');
  assert.equal(report.findings.some((item) => item.type === "possible-secret"), true);
});

test("protector transforms an annotated arithmetic function", () => {
  const result = protectSource("// @rea-protect\nexport function f(a, b) { return a * b + 2; }\n");
  assert.equal(result.report.transformed.length, 1);
  assert.match(result.code, /_s/);
});

test("unsupported function is reported rather than silently transformed", () => {
  const result = protectSource("// @rea-protect\nexport function f(a) { return Math.abs(a); }\n");
  assert.equal(result.report.transformed.length, 0);
  assert.equal(result.report.exclusions.length, 1);
});
