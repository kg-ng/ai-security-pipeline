import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runDependencyAudit } from "../scanners/dependencyAudit.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runDependencyAudit", () => {
  it("skips a directory that is not a Node project", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-dep-"));

    expect(await runDependencyAudit(dir)).toEqual([]);
  });

  it("reports that the audit could not run when there is no lockfile", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-dep-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.17.0" } }));

    const findings = await runDependencyAudit(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("dep-audit-unavailable");
    expect(findings[0].description).toContain("NOT checked");
  });
});
