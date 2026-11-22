import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "..", "cli.ts");
const run = (args: string[]) =>
  spawnSync(process.execPath, ["--import", "tsx", CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, OPENAI_API_KEY: "" },
  });

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("cli exit codes", () => {
  it("exits 1 for blocking findings and 0 once they are in the ignore file", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-cli-"));
    await writeFile(join(dir, "client.ts"), "const opts = { rejectUnauthorized: false };\n");

    expect(run(["scan", "--path", dir]).status).toBe(1);

    await writeFile(join(dir, ".ai-security-ignore"), "code-client.ts-tls-verification-disabled\n");
    const passed = run(["scan", "--path", dir]);
    expect(passed.status).toBe(0);
    expect(passed.stdout).toContain("1 finding(s) suppressed");
  });

  it("exits 2, not 1, for a usage error", () => {
    expect(run(["scan", "--fail-on", "hgih"]).status).toBe(2);
  });
});
