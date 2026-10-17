import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runSecretScan } from "../scanners/secretScan.js";

const FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP";
const FAKE_GITHUB_TOKEN = "ghp_" + "a".repeat(40);

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runSecretScan", () => {
  it("flags an AWS access key committed to source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    // Built at runtime so this source file does not itself match the AWS key pattern.
    await writeFile(join(dir, "config.ts"), `const key = "${FAKE_AWS_KEY}";\n`);

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].title).toContain("AWS Access Key");
  });

  it("flags a token committed inside a test file", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "leak.test.ts"), `const t = "${FAKE_GITHUB_TOKEN}";\n`);

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("GitHub Token");
    expect(findings[0].location).toBe("leak.test.ts");
  });

  it("returns no findings for clean source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "index.ts"), 'export const greeting = "hello world";\n');

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(0);
  });
});
