#!/usr/bin/env node
import { Command, Option } from "commander";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { runDependencyAudit } from "./scanners/dependencyAudit.js";
import { runSecretScan } from "./scanners/secretScan.js";
import { runCodePatternScan } from "./scanners/codePatternScan.js";
import { triageFindings } from "./triage.js";
import { renderMarkdownReport } from "./report.js";
import { SEVERITIES, hasBlockingFinding, parseFailOn } from "./gate.js";

const program = new Command();

program
  .name("ai-security-pipeline")
  .description(
    "Scans a project for vulnerable dependencies and leaked secrets, then uses an LLM " +
      "(or a rule-based fallback) to triage findings and suggest fixes.",
  )
  .version("0.1.0");

program
  .command("scan")
  .description("Run the security scan and print/write a Markdown report.")
  .option("-p, --path <path>", "path to the project to scan", ".")
  .option("-o, --output <file>", "write the report to a file instead of stdout")
  .addOption(
    new Option("--fail-on <severity>", "exit non-zero if a finding at/above this severity is present")
      .choices([...SEVERITIES])
      .default("critical"),
  )
  .action(async (opts: { path: string; output?: string; failOn: string }) => {
    const failOn = parseFailOn(opts.failOn);
    const cwd = resolve(opts.path);

    const [dependencyFindings, secretFindings, codePatternFindings] = await Promise.all([
      runDependencyAudit(cwd),
      runSecretScan(cwd),
      runCodePatternScan(cwd),
    ]);

    const findings = [...dependencyFindings, ...secretFindings, ...codePatternFindings];
    const triaged = await triageFindings(findings);
    const report = renderMarkdownReport(triaged, new Date().toISOString());

    if (opts.output) {
      await writeFile(opts.output, report, "utf8");
    } else {
      console.log(report);
    }

    if (hasBlockingFinding(triaged, failOn)) {
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv);
