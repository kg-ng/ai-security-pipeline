import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyIgnoreList, loadIgnoreFile } from "../ignore.js";
import type { Finding } from "../types.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("ignore file", () => {
  it("suppresses listed finding ids and supports comments", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-ignore-"));
    const path = join(dir, ".ai-security-ignore");
    await writeFile(path, "# accepted risk, see SEC-12\ncode-src/legacy.ts-weak-hash  # md5 used for etags only\n\n");

    const ignored = await loadIgnoreFile(path);
    const f = (id: string) => ({ id }) as Finding;
    const { kept, suppressed } = applyIgnoreList([f("code-src/legacy.ts-weak-hash"), f("dep-lodash")], ignored);

    expect(kept.map((x) => x.id)).toEqual(["dep-lodash"]);
    expect(suppressed.map((x) => x.id)).toEqual(["code-src/legacy.ts-weak-hash"]);
  });

  it("treats a missing ignore file as empty", async () => {
    expect((await loadIgnoreFile("/nonexistent/.ai-security-ignore")).size).toBe(0);
  });
});
