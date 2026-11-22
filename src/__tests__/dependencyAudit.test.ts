import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findingsFromLegacyAdvisories, runDependencyAudit } from "../scanners/dependencyAudit.js";

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

describe("runDependencyAudit setup problems", () => {
  it("recommends fixing the audit setup, not running npm audit fix, when it could not run", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-dep-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));

    const [finding] = await runDependencyAudit(dir);

    expect(finding.recommendation).toContain("lockfile");
    expect(finding.recommendation).not.toContain("audit fix");
  });

  it("reports Yarn Berry projects as unsupported instead of auditing them with npm", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-dep-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    await writeFile(join(dir, "yarn.lock"), "__metadata:\n  version: 8\n");

    const [finding] = await runDependencyAudit(dir);

    expect(finding.id).toBe("dep-audit-unavailable");
    expect(finding.description).toContain("Yarn 2+");
  });
});

describe("findingsFromLegacyAdvisories (pnpm / Yarn 1)", () => {
  it("groups advisories per package at the worst severity with the patched ranges", () => {
    const findings = findingsFromLegacyAdvisories([
      { module_name: "lodash", severity: "moderate", title: "ReDoS", patched_versions: ">=4.17.21" },
      { module_name: "lodash", severity: "critical", title: "Prototype Pollution", patched_versions: ">=4.17.12" },
      { module_name: "left-pad", severity: "low", title: "Bad", patched_versions: "<0.0.0" },
    ]);

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({ id: "dep-lodash", severity: "critical", description: "ReDoS; Prototype Pollution" });
    expect(findings[0].recommendation).toContain("matching >=4.17.21,");
    expect(findings[1].recommendation).toContain("No fix is available");
  });
});
