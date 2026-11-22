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

describe("runCodePatternScan precision", () => {
  const scan = async (source: string) => {
    dir = await mkdtemp(join(tmpdir(), "ai-sec-code-"));
    await writeFile(join(dir, "index.ts"), source);
    return runCodePatternScan(dir);
  };

  it("flags SQL built with interpolation and reports the line", async () => {
    const findings = await scan('const a = 1;\ndb.query(`SELECT * FROM users WHERE id = ${id}`);\n');

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("SQL");
    expect(findings[0].location).toBe("index.ts:2");
  });

  it("flags SQL whose interpolation comes before FROM", async () => {
    const findings = await scan("db.query(`select ${cols} from users`);\n");

    expect(findings.map((f) => f.title)).toEqual([expect.stringContaining("SQL")]);
  });

  it.each([
    "SELECT COUNT(*) FROM users WHERE name = ${n}",
    "SELECT u.id AS uid FROM users u WHERE id = ${id}",
    'SELECT "name" FROM t WHERE id = ${id}',
    "UPDATE users SET name = '${name}'",
    "delete from sessions where token = '${token}'",
  ])("flags interpolated SQL: %s", async (sql) => {
    const findings = await scan(`db.query(\`${sql}\`);\n`);

    expect(findings.map((f) => f.title)).toEqual([expect.stringContaining("SQL")]);
  });

  it("stays fast on adversarial input", async () => {
    const started = Date.now();
    await scan("const x = `" + "select ${".repeat(110_000) + "\n");
    await scan("const y = `" + "SELECT a FROM ${".repeat(60_000) + "`;\n");

    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("does not flag UI strings that merely contain SQL keywords", async () => {
    expect(
      await scan(
        "const a = `Please update ${user.name}, then select an option from the list`;\n" +
          "const b = `Delete ${n} items?`;\nconst c = `Select an option from ${list}`;\n",
      ),
    ).toHaveLength(0);
  });

  it("flags command injection via string concatenation", async () => {
    const findings = await scan('exec("rm -rf " + userPath);\n');

    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("ignores eval in comments and eval-named methods", async () => {
    expect(await scan("// never call eval(input) here\nconst r = engine.eval(expr);\n")).toHaveLength(0);
  });
});
