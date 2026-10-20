import fs from "node:fs/promises";
import path from "node:path";
import { parse } from "@babel/parser";
import traverseModule from "@babel/traverse";

const traverse = traverseModule.default ?? traverseModule;
const SECRET_PATTERNS = [
  { id: "private-key-marker", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i, severity: "critical" },
  { id: "credential-assignment", re: /\b(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|password)\b\s*[:=]\s*["'`][^"'`\r\n]{8,}["'`]/i, severity: "high" },
  { id: "cloud-access-key", re: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical" },
  { id: "jwt-like-token", re: /\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/, severity: "high" }
];

export function auditSource(source, filename = "input.js") {
  const findings = [];
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.re.test(lines[i])) {
        findings.push({
          type: "possible-secret",
          rule: pattern.id,
          severity: pattern.severity,
          file: filename,
          line: i + 1,
          message: "Possible hard-coded credential or private material; review manually."
        });
      }
    }
  }

  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      sourceFilename: filename,
      plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "topLevelAwait"]
    });
  } catch (error) {
    return {
      version: "0.4.0",
      file: filename,
      parseError: error.message,
      findings,
      metrics: { functions: 0, annotatedFunctions: 0, totalComplexity: 0 },
      score: null,
      scoreMeaning: "Unavailable because parsing failed."
    };
  }

  let functions = 0;
  let annotatedFunctions = 0;
  let totalComplexity = 0;
  const functionMetrics = [];

  traverse(ast, {
    Function(pathRef) {
      functions += 1;
      let complexity = 1;
      pathRef.traverse({
        Function(inner) {
          if (inner !== pathRef) inner.skip();
        },
        IfStatement() { complexity += 1; },
        ConditionalExpression() { complexity += 1; },
        ForStatement() { complexity += 1; },
        ForInStatement() { complexity += 1; },
        ForOfStatement() { complexity += 1; },
        WhileStatement() { complexity += 1; },
        DoWhileStatement() { complexity += 1; },
        CatchClause() { complexity += 1; },
        SwitchCase(switchPath) { if (switchPath.node.test) complexity += 1; },
        LogicalExpression(logicalPath) {
          if (logicalPath.node.operator === "&&" || logicalPath.node.operator === "||" || logicalPath.node.operator === "??") complexity += 1;
        }
      });
      const leading = pathRef.node.leadingComments ?? pathRef.parentPath?.node?.leadingComments ?? [];
      const annotated = leading.some((comment) => /@rea-protect\b/.test(comment.value));
      if (annotated) annotatedFunctions += 1;
      totalComplexity += complexity;
      functionMetrics.push({
        name: pathRef.node.id?.name ?? pathRef.node.key?.name ?? "(anonymous)",
        line: pathRef.node.loc?.start.line ?? null,
        complexity,
        annotated
      });
    }
  });

  const secretPenalty = findings.reduce((sum, finding) => sum + (finding.severity === "critical" ? 25 : 12), 0);
  const complexityPenalty = Math.min(30, totalComplexity);
  const score = Math.max(0, Math.min(100, 100 - secretPenalty - complexityPenalty));
  return {
    version: "0.4.0",
    file: filename,
    findings,
    metrics: { functions, annotatedFunctions, totalComplexity },
    functionMetrics,
    heuristicExposureScore: score,
    scoreMeaning: "Heuristic triage indicator only; not a probability of compromise or reconstruction."
  };
}

export async function auditFile(filename) {
  const absolute = path.resolve(filename);
  return auditSource(await fs.readFile(absolute, "utf8"), absolute);
}
