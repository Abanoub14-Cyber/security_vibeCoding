import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { v4 as uuid } from "uuid";
import type { Finding, ModuleResult, ScanConfig } from "@vibecode/shared";
import {
  DANGEROUS_CLIENT_PATTERNS,
  FIREBASE_INSECURE_PATTERNS,
  SECRET_PATTERNS,
} from "@vibecode/shared";

const execFileAsync = promisify(execFile);

const CLIENT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs",
  ".vue", ".svelte", ".astro",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next",
  ".nuxt", ".output", "coverage", "api", "server",
  "functions", "supabase/functions",
]);

async function getClientFiles(dir: string): Promise<string[]> {
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
        if (CLIENT_EXTENSIONS.has(ext)) {
          files.push(fullPath);
        }
      }
    }
  }

  await walk(dir);
  return files;
}

async function checkClientSideApiCalls(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await getClientFiles(targetPath);

  for (const filePath of files) {
    let content: string;
    try {
      const fileStat = await stat(filePath);
      if (fileStat.size > 500_000) continue;
      content = await readFile(filePath, "utf-8");
    } catch {
      continue;
    }

    const relPath = relative(targetPath, filePath);

    if (relPath.includes("server") || relPath.includes("api/") ||
        relPath.includes(".server.") || relPath.includes("edge-function")) {
      continue;
    }

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, name } of DANGEROUS_CLIENT_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            id: uuid(),
            module: "frontend-checker",
            severity: "critical",
            title: name,
            description: `Direct API call to a third-party service detected in client-side code. This exposes your API key in the browser where anyone can extract it from DevTools > Network tab.`,
            location: { file: relPath, line: i + 1 },
            remediation: "Move this API call to a server-side route (Next.js API route, Supabase Edge Function, etc.). The API key should only exist on the server.",
            evidence: line.trim().substring(0, 100),
            verified: true,
            tags: ["client-side-api", "vibe-coding"],
          });
        }
      }

      for (const [patternName, pattern] of Object.entries(SECRET_PATTERNS)) {
        if (pattern.test(line)) {
          if (!line.trim().startsWith("import") && !line.trim().startsWith("type") &&
              !line.trim().startsWith("//") && !line.trim().startsWith("*")) {
            findings.push({
              id: uuid(),
              module: "frontend-checker",
              severity: "critical",
              title: `Hardcoded secret in client component: ${patternName}`,
              description: `A ${patternName.replace(/_/g, " ")} is hardcoded in a client-side file. This will be included in the JavaScript bundle sent to every user's browser.`,
              location: { file: relPath, line: i + 1 },
              remediation: "Remove the hardcoded key. Use a server-side environment variable and proxy requests through your backend.",
              evidence: line.trim().substring(0, 60) + "...",
              tags: ["hardcoded-secret", "client-side"],
            });
            break;
          }
        }
      }
    }

    if (content.includes("fetch(") && !content.includes('"use server"') &&
        !content.includes("'use server'") && relPath.includes("app/")) {
      const hasApiCall = DANGEROUS_CLIENT_PATTERNS.some(({ pattern }) => {
        pattern.lastIndex = 0;
        return pattern.test(content);
      });
      if (hasApiCall) {
        findings.push({
          id: uuid(),
          module: "frontend-checker",
          severity: "high",
          title: "Server action missing 'use server' directive",
          description: "This file in the app/ directory makes API calls but lacks a 'use server' directive, meaning the code runs client-side.",
          location: { file: relPath },
          remediation: "Add 'use server' at the top of the file or extract the API call into a separate server action file.",
          tags: ["nextjs", "use-server"],
        });
      }
    }
  }

  return findings;
}

async function checkFirebaseRules(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ruleFiles = [
    "firestore.rules",
    "database.rules.json",
    "storage.rules",
    "firebase/firestore.rules",
  ];

  for (const ruleFile of ruleFiles) {
    try {
      const content = await readFile(join(targetPath, ruleFile), "utf-8");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of FIREBASE_INSECURE_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              id: uuid(),
              module: "frontend-checker",
              severity: "critical",
              title: name,
              description: `Insecure Firebase security rule detected. This allows unrestricted access to your database, meaning anyone can read or modify your data.`,
              location: { file: ruleFile, line: i + 1 },
              remediation: "Restrict access with proper authentication checks: `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`",
              evidence: lines[i].trim(),
              verified: true,
              tags: ["firebase", "insecure-rules"],
            });
          }
        }
      }
    } catch {
      // File doesn't exist, skip
    }
  }

  return findings;
}

async function checkBundleForSecrets(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const buildDirs = ["dist", "build", ".next/static", ".output/public"];

  for (const buildDir of buildDirs) {
    const fullBuildDir = join(targetPath, buildDir);
    try {
      await stat(fullBuildDir);
    } catch {
      continue;
    }

    const jsFiles = await getFilesRecursive(fullBuildDir, [".js", ".mjs"]);

    for (const file of jsFiles) {
      let content: string;
      try {
        const fileStat = await stat(file);
        if (fileStat.size > 5_000_000) continue;
        content = await readFile(file, "utf-8");
      } catch {
        continue;
      }

      const relPath = relative(targetPath, file);

      for (const [patternName, pattern] of Object.entries(SECRET_PATTERNS)) {
        if (pattern.test(content)) {
          findings.push({
            id: uuid(),
            module: "frontend-checker",
            severity: "critical",
            title: `Secret found in production bundle: ${patternName}`,
            description: `A ${patternName.replace(/_/g, " ")} was detected in a built JavaScript bundle. This is served to all users and is trivially extractable.`,
            location: { file: relPath },
            remediation: "Remove the secret from client code. Rebuild after moving it to a server-side environment variable.",
            tags: ["bundle-secret", "production"],
            verified: true,
          });
        }
      }
    }
  }

  return findings;
}

async function getFilesRecursive(dir: string, extensions: string[]): Promise<string[]> {
  const files: string[] = [];
  const extSet = new Set(extensions);

  async function walk(currentDir: string) {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && extSet.has(extname(entry.name).toLowerCase())) {
        files.push(fullPath);
      }
    }
  }

  await walk(dir);
  return files;
}

async function runSemgrep(targetPath: string): Promise<Finding[]> {
  try {
    const { stdout } = await execFileAsync("semgrep", [
      "--config", "auto",
      "--json",
      "--timeout", "30",
      targetPath,
    ], { timeout: 120000 });

    const results = JSON.parse(stdout);
    return (results.results || []).map((r: any) => ({
      id: uuid(),
      module: "frontend-checker" as const,
      severity: mapSemgrepSeverity(r.extra?.severity),
      title: r.check_id || "Semgrep finding",
      description: r.extra?.message || "Security issue detected by Semgrep",
      location: {
        file: relative(targetPath, r.path),
        line: r.start?.line,
      },
      remediation: r.extra?.fix || "Review and fix the identified security issue.",
      tags: ["semgrep", ...(r.extra?.metadata?.category ? [r.extra.metadata.category] : [])],
    }));
  } catch {
    return [];
  }
}

function mapSemgrepSeverity(severity?: string): Finding["severity"] {
  switch (severity?.toUpperCase()) {
    case "ERROR": return "critical";
    case "WARNING": return "high";
    case "INFO": return "medium";
    default: return "medium";
  }
}

export async function runFrontendChecker(config: ScanConfig): Promise<ModuleResult> {
  const start = Date.now();
  const targetPath = config.target.path;

  try {
    const [clientApiFindings, firebaseFindings, bundleFindings, semgrepFindings] = await Promise.all([
      checkClientSideApiCalls(targetPath),
      checkFirebaseRules(targetPath),
      checkBundleForSecrets(targetPath),
      runSemgrep(targetPath),
    ]);

    const allFindings = [
      ...clientApiFindings,
      ...firebaseFindings,
      ...bundleFindings,
      ...semgrepFindings,
    ];

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
      module: "frontend-checker",
      findings: allFindings,
      score,
      duration: Date.now() - start,
      status: hasCritical ? "failed" : hasHigh ? "warning" : allFindings.length > 0 ? "warning" : "passed",
    };
  } catch (error) {
    return {
      module: "frontend-checker",
      findings: [],
      score: 0,
      duration: Date.now() - start,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}
