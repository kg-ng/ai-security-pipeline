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
});
