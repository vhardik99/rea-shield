// /api/audit.js – Vercel Serverless Function (ESM)
// Handles POST requests with { sourceCode } or { url }
// Performs REA‑Shield static audit using the core auditSource function.

import { auditSource } from "../src/audit.mjs";

/** Helper: enable CORS for all origins */
function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

/** Vercel serverless entry point */
export default async function handler(req, res) {
  // Pre‑flight CORS handling
  if (req.method === "OPTIONS") {
    setCorsHeaders(res);
    res.status(200).end();
    return;
  }

  setCorsHeaders(res);

  if (req.method !== "POST") {
    res.status(405).json({ success: false, error: "Method not allowed" });
    return;
  }

  let payload;
  try {
    payload = await req.json();
  } catch (e) {
    res.status(400).json({ success: false, error: "Invalid JSON payload" });
    return;
  }

  const { sourceCode, url } = payload;
  if (!sourceCode && !url) {
    res
      .status(400)
      .json({ success: false, error: "Provide either 'sourceCode' or 'url'" });
    return;
  }

  let source;
  let targetLabel;
  if (sourceCode) {
    source = String(sourceCode);
    targetLabel = "inline source";
  } else {
    // Fetch remote script securely (only http/https)
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Unsupported URL protocol");
      }
      const response = await fetch(parsed.toString(), {
        method: "GET",
        headers: { "Accept": "application/javascript" },
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch script: ${response.status}`);
      }
      source = await response.text();
      targetLabel = url;
    } catch (err) {
      res
        .status(400)
        .json({ success: false, error: `Could not fetch URL – ${err.message}` });
      return;
    }
  }

  // Run REA‑Shield audit (fallback to simple heuristics if the module throws)
  let auditResult;
  try {
    auditResult = await auditSource(source, targetLabel);
  } catch (err) {
    // Simple heuristic fallback – look for hard‑coded secrets via regex patterns
    const SECRET_REGEX = /(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[^'"\s]{8,}['"]?/i;
    const findings = SECRET_REGEX.test(source) ? [{ type: "possible-secret" }] : [];
    const exposure = findings.length > 0 ? 20 : 100;
    auditResult = {
      heuristicExposureScore: exposure,
      functionMetrics: [],
    };
  }

  const exposureScore = auditResult.heuristicExposureScore ?? 0;
  const bytecodeInstructionsCount =
    (auditResult.functionMetrics || []).reduce((sum, f) => sum + (f.operations || 0), 0);

  res.status(200).json({
    success: true,
    target: targetLabel,
    exposureScore,
    bytecodeInstructionsCount,
    findings: auditResult.findings || [],
  });
}
