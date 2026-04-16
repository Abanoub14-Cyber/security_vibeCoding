import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { v4 as uuid } from "uuid";
import type { Finding, ModuleResult, ScanConfig } from "@vibecode/shared";
import {
  SECRET_PATTERNS,
  PUBLIC_ENV_PATTERNS,
} from "@vibecode/shared";

const execFileAsync = promisify(execFile);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".vue", ".svelte", ".astro",
  ".env", ".yaml", ".yml", ".json", ".toml",
  ".py", ".rb", ".go", ".rs",
  ".html", ".htm", ".css", ".scss",
  ".md", ".txt", ".cfg", ".ini", ".conf",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next",
  ".nuxt", ".output", "coverage", ".turbo", ".cache",
  "vendor", "__pycache__",
]);

async function getFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string) {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (SCAN_EXTENSIONS.has(ext) || entry.name.startsWith(".env") || entry.name === "Dockerfile") {
          files.push(fullPath);
        }
      }
    }
  }

  await walk(dir);
  return files;
}

async function runGitleaks(targetPath: string): Promise<Finding[]> {
  try {
    const { stdout } = await execFileAsync("gitleaks", [
      "detect",
      "--source", targetPath,
      "--report-format", "json",
      "--report-path", "/dev/stdout",
      "--no-git",
    ], { timeout: 60000 });

    const results = JSON.parse(stdout);
    return results.map((r: any) => ({
      id: uuid(),
      module: "secret-scanner" as const,
      severity: "critical" as const,
      title: `Secret detected: ${r.Description || r.RuleID}`,
      description: `Gitleaks found a potential secret (${r.RuleID}) in your codebase. This credential could be exploited if exposed.`,
      location: {
        file: r.File,
        line: r.StartLine,
      },
      remediation: "Remove the secret from source code. Rotate the credential immediately. Use environment variables or a secret manager instead.",
      evidence: r.Match ? `${r.Match.substring(0, 8)}...${r.Match.substring(r.Match.length - 4)}` : undefined,
      verified: false,
      tags: ["gitleaks", r.RuleID],
    }));
  } catch {
    return [];
  }
}

async function runTrufflehog(targetPath: string): Promise<Finding[]> {
  try {
    const { stdout } = await execFileAsync("trufflehog", [
      "filesystem",
      targetPath,
      "--json",
      "--no-update",
    ], { timeout: 120000 });

    const lines = stdout.trim().split("\n").filter(Boolean);
    return lines.map((line) => {
      const r = JSON.parse(line);
      return {
        id: uuid(),
        module: "secret-scanner" as const,
        severity: r.Verified ? "critical" as const : "high" as const,
        title: `${r.Verified ? "VERIFIED " : ""}Secret: ${r.DetectorName || "Unknown"}`,
        description: `TruffleHog detected a ${r.Verified ? "verified (live!)" : "potential"} ${r.DetectorName} secret.${r.Verified ? " This credential is confirmed active and must be rotated immediately." : ""}`,
        location: {
          file: r.SourceMetadata?.Data?.Filesystem?.file || "unknown",
          line: r.SourceMetadata?.Data?.Filesystem?.line,
        },
        remediation: r.Verified
          ? "URGENT: This secret is verified as active. Rotate it immediately, then remove from code."
          : "Remove the secret from source code. Use environment variables or a secret manager.",
        evidence: r.Raw ? `${r.Raw.substring(0, 8)}...` : undefined,
        verified: r.Verified || false,
        tags: ["trufflehog", r.DetectorName, ...(r.Verified ? ["verified"] : [])],
      };
    });
  } catch {
    return [];
  }
}

async function customSecretScan(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await getFiles(targetPath);

  for (const filePath of files) {
    let content: string;
    try {
      const fileStat = await stat(filePath);
      if (fileStat.size > 1_000_000) continue;
      content = await readFile(filePath, "utf-8");
    } catch {
      continue;
    }

    const relPath = relative(targetPath, filePath);
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const [patternName, pattern] of Object.entries(SECRET_PATTERNS)) {
        if (pattern.test(line)) {
          if (relPath.includes("test") || relPath.includes("example") || relPath.includes("mock")) continue;
          if (line.trim().startsWith("//") && !line.includes("=")) continue;

          findings.push({
            id: uuid(),
            module: "secret-scanner",
            severity: patternName.includes("PRIVATE_KEY") || patternName.includes("SERVICE_ROLE")
              ? "critical"
              : "high",
            title: `Custom rule: ${patternName.replace(/_/g, " ").toLowerCase()}`,
            description: `A potential ${patternName.replace(/_/g, " ").toLowerCase()} was detected in your source code.`,
            location: { file: relPath, line: i + 1 },
            remediation: "Move this value to a server-side environment variable. Never expose secrets in client-accessible code.",
            evidence: line.trim().substring(0, 60) + (line.trim().length > 60 ? "..." : ""),
            verified: false,
            tags: ["custom-rule", patternName.toLowerCase()],
          });
          break;
        }
      }

      for (const envPattern of PUBLIC_ENV_PATTERNS) {
        if (envPattern.test(line)) {
          findings.push({
            id: uuid(),
            module: "secret-scanner",
            severity: "critical",
            title: "Secret in public environment variable",
            description: "A secret/key/token is set via a public-prefixed environment variable (VITE_, NEXT_PUBLIC_, etc.). These values are embedded in the client bundle and visible to anyone.",
            location: { file: relPath, line: i + 1 },
            remediation: "Move this to a server-side env variable (without the VITE_/NEXT_PUBLIC_ prefix). Call it via an API route or Edge Function instead.",
            evidence: line.trim().substring(0, 80),
            verified: true,
            tags: ["vibe-coding", "public-env-secret"],
          });
        }
      }
    }
  }

  return findings;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.location.file}:${f.location.line}:${f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function runSecretScanner(config: ScanConfig): Promise<ModuleResult> {
  const start = Date.now();
  const targetPath = config.target.path;

  try {
    const [gitleaksFindings, trufflehogFindings, customFindings] = await Promise.all([
      runGitleaks(targetPath),
      runTrufflehog(targetPath),
      customSecretScan(targetPath),
    ]);

    const allFindings = deduplicateFindings([
      ...gitleaksFindings,
      ...trufflehogFindings,
      ...customFindings,
    ]);

    let score = 100;
    for (const f of allFindings) {
      if (f.severity === "critical") score -= 25;
      else if (f.severity === "high") score -= 15;
      else if (f.severity === "medium") score -= 8;
      else if (f.severity === "low") score -= 3;
    }
    score = Math.max(0, score);

    const hasCritical = allFindings.some((f) => f.severity === "critical");
    const hasHigh = allFindings.some((f) => f.severity === "high");

    return {
      module: "secret-scanner",
      findings: allFindings,
      score,
      duration: Date.now() - start,
      status: hasCritical ? "failed" : hasHigh ? "warning" : allFindings.length > 0 ? "warning" : "passed",
    };
  } catch (error) {
    return {
      module: "secret-scanner",
      findings: [],
      score: 0,
      duration: Date.now() - start,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}
