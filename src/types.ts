export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable identifier (no line numbers), usable in a `.ai-security-ignore` file. */
  id: string;
  source: "dependency-audit" | "secret-scan" | "code-pattern-scan";
  /** Identifies the rule/check that produced the finding (used for SARIF rule ids). */
  ruleId?: string;
  title: string;
  description: string;
  severity: Severity;
  /** Human-readable location, e.g. `src/db.ts:12`. */
  location?: string;
  /** Path relative to the scanned root, using `/` separators. */
  file?: string;
  /** 1-based line of the first match. */
  line?: number;
  /** Scanner-provided remediation hint, used by rule-based triage and given to the LLM as context. */
  recommendation?: string;
}

export interface TriagedFinding extends Finding {
  priority: number; // 1 (fix now) – 5 (backlog)
  recommendation: string;
  triagedBy: "llm" | "rules";
}

export interface ScanResult {
  findings: Finding[];
  scannedAt: string;
}
