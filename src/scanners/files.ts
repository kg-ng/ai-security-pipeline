import { execFile } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface ScanOptions {
  /** Pre-computed file list (see `listProjectFiles`), so several scanners can share one walk. */
  files?: string[];
}

/** Files larger than this are skipped: they are almost always lockfiles, bundles, or binary assets. */
export const MAX_FILE_BYTES = 1024 * 1024;

/** Put this marker in a comment on the same line as a match, or the line above it, to suppress it. */
export const INLINE_IGNORE_MARKER = "ai-security-ignore";

/** Never scanned, at any depth. `.ai-security-pipeline` is where the reusable workflow checks out this tool. */
const ALWAYS_IGNORED_DIRS = new Set(["node_modules", ".git", ".ai-security-pipeline"]);

/** Build output skipped at the project root when the project is not a git work tree (otherwise .gitignore decides). */
const ROOT_ARTIFACT_DIRS = new Set(["dist", "build", "coverage", ".next"]);

/**
 * Lists the files to scan as `/`-separated paths relative to `cwd`.
 *
 * Inside a git work tree this is every tracked file plus untracked files that are not
 * gitignored, so the scan sees what would be committed. Outside git it walks the tree.
 */
export async function listProjectFiles(cwd: string): Promise<string[]> {
  const files = (await listGitFiles(cwd)) ?? (await walk(cwd, ""));
  return files.filter((f) => !f.split("/").some((segment) => ALWAYS_IGNORED_DIRS.has(segment)));
}

async function listGitFiles(cwd: string): Promise<string[] | null> {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
      { cwd, maxBuffer: 256 * 1024 * 1024 },
    );
    // A trailing slash marks a nested repository rather than a file.
    return stdout.split("\0").filter((f) => f.length > 0 && !f.endsWith("/"));
  } catch {
    return null; // not a git work tree, or git is unavailable
  }
}

async function walk(root: string, relDir: string): Promise<string[]> {
  const entries = await readdir(join(root, relDir), { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (ALWAYS_IGNORED_DIRS.has(entry.name)) continue;
    if (relDir === "" && ROOT_ARTIFACT_DIRS.has(entry.name)) continue;
    const relPath = relDir === "" ? entry.name : `${relDir}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await walk(root, relPath)));
    } else if (entry.isFile()) {
      files.push(relPath);
    }
  }
  return files;
}

/** Reads a file as UTF-8 text, or returns null for missing, oversized, or binary (NUL-containing) files. */
export async function readTextFile(path: string): Promise<string | null> {
  try {
    if ((await stat(path)).size > MAX_FILE_BYTES) return null;
    const buffer = await readFile(path);
    if (buffer.subarray(0, 8192).includes(0)) return null;
    return buffer.toString("utf8");
  } catch {
    return null;
  }
}

export interface MatchFilters {
  /** Reject a match by the full text of the line it starts on. */
  skipLine?: (line: string) => boolean;
  /** Reject a match by its own text. */
  accept?: (match: string) => boolean;
}

/**
 * Returns the 1-based line numbers of every match of `regex` (which must have the `g` flag),
 * excluding matches suppressed by an inline ignore marker or rejected by `filters`.
 */
export function matchLines(content: string, regex: RegExp, filters: MatchFilters = {}): number[] {
  const lines = content.split("\n");
  const lineStarts: number[] = [];
  let offset = 0;
  for (const line of lines) {
    lineStarts.push(offset);
    offset += line.length + 1;
  }

  const lineOf = (index: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };

  const result: number[] = [];
  for (const match of content.matchAll(regex)) {
    const i = lineOf(match.index ?? 0);
    const text = lines[i];
    if (text.includes(INLINE_IGNORE_MARKER) || (i > 0 && lines[i - 1].includes(INLINE_IGNORE_MARKER))) continue;
    if (filters.skipLine?.(text)) continue;
    if (filters.accept && !filters.accept(match[0])) continue;
    if (result[result.length - 1] !== i + 1) result.push(i + 1);
  }
  return result;
}

/** "line 3" / "lines 3, 7, 12 and 4 more" */
export function describeLines(lines: number[], max = 10): string {
  const shown = lines.slice(0, max).join(", ");
  const extra = lines.length > max ? ` and ${lines.length - max} more` : "";
  return `${lines.length === 1 ? "line" : "lines"} ${shown}${extra}`;
}
