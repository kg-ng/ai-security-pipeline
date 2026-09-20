export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  source: "dependency-audit" | "secret-scan";
  title: string;
  description: string;
  severity: Severity;
  location?: string;
}

export interface TriagedFinding extends Finding {
  priority: number; // 1 (fix now) – 5 (backlog)
  recommendation: string;
}

export interface ScanResult {
  findings: Finding[];
  scannedAt: string;
}
