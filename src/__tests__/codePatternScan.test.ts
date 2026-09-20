import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCodePatternScan } from "../scanners/codePatternScan.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runCodePatternScan", () => {
  it("flags eval() usage", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-code-"));
    await writeFile(join(dir, "index.ts"), 'export function run(input: string) {\n  return eval(input);\n}\n');

    const findings = await runCodePatternScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("eval");
  });

  it("flags command injection via interpolated exec", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-code-"));
    await writeFile(
      join(dir, "run.ts"),
      'import { exec } from "node:child_process";\nexport function run(name: string) {\n  exec(`echo ${name}`);\n}\n',
    );

    const findings = await runCodePatternScan(dir);

    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("flags disabled TLS verification", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-code-"));
    await writeFile(join(dir, "client.ts"), "const opts = { rejectUnauthorized: false };\n");

    const findings = await runCodePatternScan(dir);

    expect(findings.some((f) => f.title.includes("TLS"))).toBe(true);
  });

  it("returns no findings for clean source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-code-"));
    await writeFile(join(dir, "index.ts"), 'export const add = (a: number, b: number) => a + b;\n');

    const findings = await runCodePatternScan(dir);

    expect(findings).toHaveLength(0);
  });
});
