import type { Severity, TriagedFinding } from "./types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub code scanning maps this 0–10 score to its own severity labels. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

/** Renders findings as SARIF 2.1.0, e.g. for upload to GitHub code scanning. */
export function renderSarifReport(findings: TriagedFinding[], toolVersion: string): string {
  const rules = new Map<string, { id: string; shortDescription: { text: string }; properties: Record<string, string> }>();
  const ruleIdOf = (f: TriagedFinding) => f.ruleId ?? f.source;

  for (const f of findings) {
    const id = ruleIdOf(f);
    const existing = rules.get(id);
    // A rule's severity is the worst severity among its results.
    if (!existing || Number(SECURITY_SEVERITY[f.severity]) > Number(existing.properties["security-severity"])) {
      rules.set(id, {
        id,
        shortDescription: { text: f.source === "dependency-audit" ? "Vulnerable dependency" : f.title },
        properties: { "security-severity": SECURITY_SEVERITY[f.severity] },
      });
    }
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ai-security-pipeline",
            version: toolVersion,
            informationUri: "https://github.com/kg-ng/ai-security-pipeline",
            rules: [...rules.values()],
          },
        },
        results: findings.map((f) => ({
          ruleId: ruleIdOf(f),
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.description} Recommendation: ${f.recommendation}` },
          partialFingerprints: { findingId: f.id },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file ?? "package.json" },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
          properties: { priority: f.priority, triagedBy: f.triagedBy },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
