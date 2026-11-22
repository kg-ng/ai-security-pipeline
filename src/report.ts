import { SEVERITIES } from "./gate.js";
import type { TriagedFinding } from "./types.js";

const SEVERITY_EMOJI: Record<TriagedFinding["severity"], string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

export interface ReportOptions {
  /** Number of findings removed by the ignore file, so suppressions stay visible. */
  suppressed?: number;
}

const ZERO_WIDTH_SPACE = "\u200B";

/**
 * Finding fields come from scanned file names, advisory text, or LLM output, and the report
 * is posted as a PR comment. Keep each value inside one table cell and render it as inert
 * text: no links, images, HTML, @mentions, or formatting.
 *
 * GitHub resolves @mentions and autolinks after decoding entities, so those are broken
 * with a zero-width space rather than escaped.
 */
export function cell(text: string): string {
  return text
    .replace(/\r?\n/g, " ")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\\`*_[\]|~!]/g, (c) => `\\${c}`)
    .replace(/@/g, `@${ZERO_WIDTH_SPACE}`)
    .replace(/:\/\//g, `:${ZERO_WIDTH_SPACE}//`)
    .replace(/\bwww\./gi, (m) => `${m.slice(0, 3)}${ZERO_WIDTH_SPACE}.`);
}

function triageSummary(findings: TriagedFinding[]): string {
  const llm = findings.filter((f) => f.triagedBy === "llm").length;
  if (llm === 0) return "rule-based";
  if (llm === findings.length) return "LLM-assisted";
  return `LLM-assisted (${findings.length - llm} fell back to rules)`;
}

/** Renders triaged findings as a Markdown report suitable for a PR comment or CI artifact. */
export function renderMarkdownReport(findings: TriagedFinding[], scannedAt: string, options: ReportOptions = {}): string {
  const suppressedNote = options.suppressed
    ? ` ${options.suppressed} finding(s) suppressed by the ignore file.`
    : "";

  if (findings.length === 0) {
    return `## 🛡️ AI Security Pipeline Report\n\nNo findings — scan completed at ${scannedAt}.${suppressedNote}`;
  }

  const sorted = [...findings].sort(
    (a, b) => a.priority - b.priority || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
  );
  const rows = sorted
    .map(
      (f) =>
        `| ${SEVERITY_EMOJI[f.severity]} ${f.severity} | ${f.priority} | ${cell(f.title)}<br><sub>${cell(f.description)}</sub><br><sub>id: ${cell(f.id)}</sub> | ${cell(f.recommendation)} | ${cell(f.location ?? "-")} |`,
    )
    .join("\n");

  const counts = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");

  return [
    "## 🛡️ AI Security Pipeline Report",
    "",
    `Scanned at ${scannedAt} — ${findings.length} finding(s): ${counts}. Triage: ${triageSummary(findings)}.${suppressedNote}`,
    "",
    "| Severity | Priority | Finding | Recommendation | Location |",
    "| --- | --- | --- | --- | --- |",
    rows,
  ].join("\n");
}
