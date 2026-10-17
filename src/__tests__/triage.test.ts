import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { triageFindings } from "../triage.js";
import type { Finding } from "../types.js";

const finding = (over: Partial<Finding>): Finding => ({
  id: "f1",
  source: "secret-scan",
  title: "t",
  description: "d",
  severity: "critical",
  ...over,
});

let savedKey: string | undefined;

beforeEach(() => {
  savedKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
});

afterEach(() => {
  if (savedKey === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = savedKey;
});

describe("triageFindings (rule-based fallback)", () => {
  it("returns an empty list for no findings", async () => {
    expect(await triageFindings([])).toEqual([]);
  });

  it("maps severity to priority and picks a recommendation by source", async () => {
    const out = await triageFindings([
      finding({ id: "a", source: "secret-scan", severity: "critical" }),
      finding({ id: "b", source: "dependency-audit", severity: "medium" }),
      finding({ id: "c", source: "code-pattern-scan", severity: "info" }),
    ]);

    expect(out.map((f) => f.priority)).toEqual([1, 3, 5]);
    expect(out[0].recommendation).toContain("Rotate");
    expect(out[1].recommendation).toContain("npm audit fix");
    expect(out[2].recommendation).toContain("Review and remediate");
  });
});
