import { describe, expect, it } from "vitest";
import { renderSarifReport } from "../sarif.js";

describe("renderSarifReport", () => {
  it("emits one rule per rule id and results with file/line locations", () => {
    const sarif = JSON.parse(
      renderSarifReport(
        [
          {
            id: "code-a.ts-sql-injection",
            ruleId: "code/sql-injection",
            source: "code-pattern-scan",
            title: "SQL",
            description: "d",
            severity: "high",
            file: "a.ts",
            line: 7,
            priority: 2,
            recommendation: "r",
            triagedBy: "rules",
          },
        ],
        "1.2.3",
      ),
    );

    const run = sarif.runs[0];
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(["code/sql-injection"]);
    expect(run.results[0]).toMatchObject({
      ruleId: "code/sql-injection",
      level: "error",
      locations: [{ physicalLocation: { artifactLocation: { uri: "a.ts" }, region: { startLine: 7 } } }],
    });
  });
});
