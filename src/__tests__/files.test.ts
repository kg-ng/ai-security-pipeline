import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listProjectFiles } from "../scanners/files.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("listProjectFiles", () => {
  it("skips build output only at the root when walking a non-git directory", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-files-"));
    await mkdir(join(dir, "build"));
    await mkdir(join(dir, "src", "build"), { recursive: true });
    await mkdir(join(dir, "node_modules", "x"), { recursive: true });
    await writeFile(join(dir, "build", "out.js"), "");
    await writeFile(join(dir, "src", "build", "config.ts"), "");
    await writeFile(join(dir, "node_modules", "x", "index.js"), "");

    expect(await listProjectFiles(dir)).toEqual(["src/build/config.ts"]);
  });

  it("honors .gitignore inside a git work tree", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-files-"));
    execFileSync("git", ["init", "-q"], { cwd: dir });
    await writeFile(join(dir, ".gitignore"), "generated/\n");
    await mkdir(join(dir, "generated"));
    await writeFile(join(dir, "generated", "big.js"), "");
    await writeFile(join(dir, "app.ts"), "");

    expect((await listProjectFiles(dir)).sort()).toEqual([".gitignore", "app.ts"]);
  });
});
