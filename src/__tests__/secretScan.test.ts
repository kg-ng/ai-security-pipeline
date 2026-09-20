import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runSecretScan } from "../scanners/secretScan.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runSecretScan", () => {
  it("flags an AWS access key committed to source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "config.ts"), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].title).toContain("AWS Access Key");
  });

  it("returns no findings for clean source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "index.ts"), 'export const greeting = "hello world";\n');

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(0);
  });
});
