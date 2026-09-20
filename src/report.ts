import type { TriagedFinding } from "./types.js";

const SEVERITY_EMOJI: Record<TriagedFinding["severity"], string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

/** Renders triaged findings as a Markdown report suitable for a PR comment or CI artifact. */
export function renderMarkdownReport(findings: TriagedFinding[], scannedAt: string): string {
  if (findings.length === 0) {
    return `## 🛡️ AI Security Pipeline Report\n\nNo findings — scan completed at ${scannedAt}.`;
  }

  const sorted = [...findings].sort((a, b) => a.priority - b.priority);
  const rows = sorted
    .map(
      (f) =>
        `| ${SEVERITY_EMOJI[f.severity]} ${f.severity} | ${f.priority} | ${f.title} | ${f.recommendation} | ${f.location ?? "-"} |`,
    )
    .join("\n");

  const criticalCount = findings.filter((f) => f.severity === "critical").length;

  return [
    "## 🛡️ AI Security Pipeline Report",
    "",
    `Scanned at ${scannedAt} — ${findings.length} finding(s), ${criticalCount} critical.`,
    "",
    "| Severity | Priority | Finding | Recommendation | Location |",
    "| --- | --- | --- | --- | --- |",
    rows,
  ].join("\n");
}
