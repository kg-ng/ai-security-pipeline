import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseTriageResponse, triageFindings } from "../triage.js";
import type { Finding } from "../types.js";

const create = vi.fn();
vi.mock("openai", () => ({
  default: class {
    chat = { completions: { create } };
  },
}));

const finding = (over: Partial<Finding>): Finding => ({
  id: "f1",
  source: "secret-scan",
  title: "t",
  description: "d",
  severity: "critical",
  ...over,
});

const reply = (content: string) => ({ choices: [{ message: { content } }] });

let savedKey: string | undefined;

beforeEach(() => {
  savedKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
  create.mockReset();
});

afterEach(() => {
  if (savedKey === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = savedKey;
  vi.restoreAllMocks();
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
    expect(out.every((f) => f.triagedBy === "rules")).toBe(true);
  });

  it("prefers the scanner's own recommendation", async () => {
    const [out] = await triageFindings([finding({ recommendation: "Use parameterized queries." })]);

    expect(out.recommendation).toBe("Use parameterized queries.");
  });
});

describe("triageFindings (LLM)", () => {
  beforeEach(() => {
    process.env.OPENAI_API_KEY = "test-key";
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("accepts a fenced JSON reply and falls back per finding the model skipped", async () => {
    create.mockResolvedValue(
      reply('```json\n{"findings":[{"id":"a","priority":2,"recommendation":"Rotate the AWS key."}]}\n```'),
    );

    const out = await triageFindings([finding({ id: "a" }), finding({ id: "b", severity: "low" })]);

    expect(out[0]).toMatchObject({ priority: 2, recommendation: "Rotate the AWS key.", triagedBy: "llm" });
    expect(out[1]).toMatchObject({ priority: 4, triagedBy: "rules" });
  });

  it("falls back to rules and warns when the model call fails", async () => {
    create.mockRejectedValue(new Error("timeout"));

    const out = await triageFindings([finding({ id: "a" })]);

    expect(out[0].triagedBy).toBe("rules");
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("timeout"));
  });
});

describe("parseTriageResponse", () => {
  it("accepts a bare array and rejects out-of-range priorities", () => {
    expect(parseTriageResponse('[{"id":"a","priority":1,"recommendation":"x"}]')).toHaveLength(1);
    expect(parseTriageResponse('[{"id":"a","priority":9,"recommendation":"x"}]')).toBeNull();
    expect(parseTriageResponse("not json")).toBeNull();
  });
});
