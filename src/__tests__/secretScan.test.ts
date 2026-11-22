import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runSecretScan } from "../scanners/secretScan.js";

// Fake secrets are built at runtime so this source file does not itself match the patterns.
const FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP";
const FAKE_GITHUB_TOKEN = "ghp_" + "a".repeat(40);
const FAKE_OPENAI_KEY = "sk-" + "proj-" + "A1b2".repeat(20);
const PKCS8_HEADER = "-----BEGIN " + "PRIVATE KEY-----";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runSecretScan", () => {
  it("flags an AWS access key committed to source, with its line number", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "config.ts"), `// config\nconst key = "${FAKE_AWS_KEY}";\n`);

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].title).toContain("AWS Access Key");
    expect(findings[0].location).toBe("config.ts:2");
    expect(findings[0].description).not.toContain(FAKE_AWS_KEY);
  });

  it("flags a token committed inside a test file", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "leak.test.ts"), `const t = "${FAKE_GITHUB_TOKEN}";\n`);

    const findings = await runSecretScan(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("GitHub Token");
    expect(findings[0].location).toBe("leak.test.ts:1");
  });

  it("flags a PKCS#8 private key and an OpenAI project key", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "key.pem"), `${PKCS8_HEADER}\nMIIE...\n`);
    await writeFile(join(dir, ".env"), `OPENAI_API_KEY=${FAKE_OPENAI_KEY}\n`);

    const titles = (await runSecretScan(dir)).map((f) => f.title);

    expect(titles).toEqual(
      expect.arrayContaining([expect.stringContaining("Private Key"), expect.stringContaining("OpenAI API Key")]),
    );
  });

  it("skips binary files", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "blob.bin"), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(FAKE_AWS_KEY)]));

    expect(await runSecretScan(dir)).toHaveLength(0);
  });

  it("honors an inline ai-security-ignore marker", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "docs.ts"), `const example = "${FAKE_AWS_KEY}"; // ai-security-ignore\n`);

    expect(await runSecretScan(dir)).toHaveLength(0);
  });

  it("returns no findings for clean source", async () => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-"));
    await writeFile(join(dir, "index.ts"), 'export const greeting = "hello world";\n');

    expect(await runSecretScan(dir)).toHaveLength(0);
  });
});
