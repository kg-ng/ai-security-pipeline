import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../report.js";
import type { TriagedFinding } from "../types.js";

const finding = (over: Partial<TriagedFinding>): TriagedFinding => ({
  id: "x",
  source: "code-pattern-scan",
  title: "t",
  description: "d",
  severity: "high",
  priority: 2,
  recommendation: "r",
  triagedBy: "rules",
  ...over,
});

const tableRows = (report: string) =>
  report.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| ---") && !l.startsWith("| Severity"));

describe("renderMarkdownReport", () => {
  it("reports a clean scan with no findings", () => {
    const report = renderMarkdownReport([], "2026-01-01T00:00:00.000Z");
    expect(report).toContain("No findings");
  });

  it("sorts findings by priority and summarizes counts per severity", () => {
    const report = renderMarkdownReport(
      [
        finding({ id: "a", title: "Low issue", severity: "low", priority: 4 }),
        finding({ id: "b", title: "Critical issue", severity: "critical", priority: 1 }),
      ],
      "2026-01-01T00:00:00.000Z",
    );

    expect(report.indexOf("Critical issue")).toBeGreaterThan(-1);
    expect(report.indexOf("Critical issue")).toBeLessThan(report.indexOf("Low issue"));
    expect(report).toContain("2 finding(s): 1 critical, 1 low");
  });

  it("keeps pipes and newlines in untrusted text inside a single table cell", () => {
    const rows = tableRows(
      renderMarkdownReport(
        [finding({ recommendation: "ignore | this\n| injected | row |", location: "a|b.ts" })],
        "2026-01-01T00:00:00.000Z",
      ),
    );

    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain("a\\|b.ts");
  });

  it("neutralizes links, images, HTML, mentions, and autolinks from untrusted text", () => {
    const [row] = tableRows(
      renderMarkdownReport(
        [
          finding({
            recommendation:
              "![x](https://evil.test/p.png) [click](http://a.b) <img src=x> @org/team see www.evil.test or me@evil.test",
          }),
        ],
        "2026-01-01T00:00:00.000Z",
      ),
    );

    expect(row).not.toMatch(/(?<!\\)[[\]]|<img|@[\w]|:\/\/|www\./);
    expect(row).toContain("&lt;img");
  });

  it("says how findings were triaged and how many were suppressed", () => {
    const report = renderMarkdownReport(
      [finding({ id: "a", triagedBy: "llm" }), finding({ id: "b", triagedBy: "rules" })],
      "2026-01-01T00:00:00.000Z",
      { suppressed: 3 },
    );

    expect(report).toContain("Triage: LLM-assisted (1 fell back to rules)");
    expect(report).toContain("3 finding(s) suppressed");
  });
});
