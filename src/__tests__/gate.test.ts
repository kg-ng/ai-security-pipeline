import { describe, expect, it } from "vitest";
import { hasBlockingFinding, parseFailOn } from "../gate.js";

describe("parseFailOn", () => {
  it("accepts every known severity", () => {
    for (const s of ["critical", "high", "medium", "low", "info"]) {
      expect(parseFailOn(s)).toBe(s);
    }
  });

  it("rejects a typo instead of silently disabling the gate", () => {
    expect(() => parseFailOn("hgih")).toThrow(/Invalid --fail-on/);
  });
});

describe("hasBlockingFinding", () => {
  it("blocks on a finding at the threshold", () => {
    expect(hasBlockingFinding([{ severity: "high" }], "high")).toBe(true);
  });

  it("blocks on a finding above the threshold", () => {
    expect(hasBlockingFinding([{ severity: "critical" }], "medium")).toBe(true);
  });

  it("does not block on findings below the threshold", () => {
    expect(hasBlockingFinding([{ severity: "medium" }, { severity: "low" }], "high")).toBe(false);
  });

  it("does not block when there are no findings", () => {
    expect(hasBlockingFinding([], "info")).toBe(false);
  });
});
