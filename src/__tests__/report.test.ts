import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../report.js";
import type { TriagedFinding } from "../types.js";

describe("renderMarkdownReport", () => {
  it("reports a clean scan with no findings", () => {
    const report = renderMarkdownReport([], "2026-01-01T00:00:00.000Z");
    expect(report).toContain("No findings");
  });

  it("sorts findings by priority and includes severity emoji", () => {
    const findings: TriagedFinding[] = [
      {
        id: "a",
        source: "dependency-audit",
        title: "Low issue",
        description: "d",
        severity: "low",
        priority: 4,
        recommendation: "r",
      },
      {
        id: "b",
        source: "secret-scan",
        title: "Critical issue",
        description: "d",
        severity: "critical",
        priority: 1,
        recommendation: "r",
      },
    ];

    const report = renderMarkdownReport(findings, "2026-01-01T00:00:00.000Z");
    const criticalIndex = report.indexOf("Critical issue");
    const lowIndex = report.indexOf("Low issue");
    expect(criticalIndex).toBeGreaterThan(-1);
    expect(criticalIndex).toBeLessThan(lowIndex);
  });

  it("keeps pipes and newlines in untrusted text inside a single table cell", () => {
    const findings: TriagedFinding[] = [
      {
        id: "x",
        source: "code-pattern-scan",
        title: "t",
        description: "d",
        severity: "high",
        priority: 2,
        recommendation: "ignore | this\n| injected | row |",
        location: "a|b.ts",
      },
    ];

    const lines = renderMarkdownReport(findings, "2026-01-01T00:00:00.000Z").split("\n");
    const rows = lines.filter((l) => l.startsWith("| ") && !l.startsWith("| ---") && !l.startsWith("| Severity"));

    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain("a\\|b.ts");
  });
});
