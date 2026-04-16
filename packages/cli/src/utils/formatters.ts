import chalk from "chalk";
import type { ScanReport, Finding, ModuleResult } from "@vibecode/shared";

const SEVERITY_COLORS: Record<string, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.dim,
};

const SEVERITY_ICONS: Record<string, string> = {
  critical: "!!",
  high: "!",
  medium: "~",
  low: "-",
  info: "i",
};

const STATUS_ICONS: Record<string, string> = {
  passed: chalk.green("PASS"),
  failed: chalk.red("FAIL"),
  warning: chalk.yellow("WARN"),
  error: chalk.red("ERR "),
  skipped: chalk.dim("SKIP"),
};

const GRADE_COLORS: Record<string, (text: string) => string> = {
  A: chalk.green.bold,
  B: chalk.green,
  C: chalk.yellow,
  D: chalk.red,
  F: chalk.bgRed.white.bold,
};

function formatScore(score: number): string {
  if (score >= 90) return chalk.green.bold(`${score}`);
  if (score >= 75) return chalk.green(`${score}`);
  if (score >= 60) return chalk.yellow(`${score}`);
  if (score >= 40) return chalk.red(`${score}`);
  return chalk.bgRed.white.bold(` ${score} `);
}

function formatGrade(grade: string): string {
  const colorFn = GRADE_COLORS[grade] || chalk.dim;
  return colorFn(` ${grade} `);
}

function formatModuleResult(result: ModuleResult): string {
  const lines: string[] = [];
  const status = STATUS_ICONS[result.status] || result.status;
  const score = formatScore(result.score);
  const duration = `${result.duration}ms`;

  const moduleNames: Record<string, string> = {
    "secret-scanner": "Secret Scanner",
    "frontend-checker": "Frontend/API Checker",
    "database-checker": "Database Exposure",
    "agent-checker": "AI Agent Risk",
  };

  const name = moduleNames[result.module] || result.module;

  lines.push(`  ${status}  ${chalk.bold(name.padEnd(24))} Score: ${score.padStart(3)}  (${chalk.dim(duration)})`);

  if (result.error) {
    lines.push(`        ${chalk.red(`Error: ${result.error}`)}`);
  }

  if (result.findings.length > 0) {
    const critical = result.findings.filter((f) => f.severity === "critical").length;
    const high = result.findings.filter((f) => f.severity === "high").length;
    const medium = result.findings.filter((f) => f.severity === "medium").length;
    const low = result.findings.filter((f) => f.severity === "low").length;

    const counts: string[] = [];
    if (critical > 0) counts.push(chalk.red(`${critical} critical`));
    if (high > 0) counts.push(chalk.red(`${high} high`));
    if (medium > 0) counts.push(chalk.yellow(`${medium} medium`));
    if (low > 0) counts.push(chalk.blue(`${low} low`));

    if (counts.length > 0) {
      lines.push(`        Findings: ${counts.join(", ")}`);
    }
  }

  return lines.join("\n");
}

function formatFinding(finding: Finding, index: number): string {
  const lines: string[] = [];
  const severityFn = SEVERITY_COLORS[finding.severity] || chalk.dim;
  const icon = SEVERITY_ICONS[finding.severity] || " ";

  lines.push(`  ${chalk.dim(`${index + 1}.`)} ${severityFn(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);

  if (finding.location.file) {
    const loc = finding.location.line
      ? `${finding.location.file}:${finding.location.line}`
      : finding.location.file;
    lines.push(`     ${chalk.dim("Location:")} ${loc}`);
  }
  if (finding.location.table) {
    lines.push(`     ${chalk.dim("Table:")} ${finding.location.table}`);
  }

  lines.push(`     ${chalk.dim(finding.description)}`);

  if (finding.evidence) {
    lines.push(`     ${chalk.dim("Evidence:")} ${chalk.yellow(finding.evidence)}`);
  }

  lines.push(`     ${chalk.cyan("Fix:")} ${finding.remediation.split("\n")[0]}`);

  if (finding.verified) {
    lines.push(`     ${chalk.red.bold("VERIFIED")} — This issue has been confirmed exploitable`);
  }

  return lines.join("\n");
}

export function formatTextReport(report: ScanReport): string {
  const lines: string[] = [];

  // Header with score
  lines.push(chalk.bold("  ─── Scan Results ───────────────────────────────────"));
  lines.push("");
  lines.push(`  Overall Score: ${formatScore(report.overallScore)}/100  Grade: ${formatGrade(report.grade)}`);
  lines.push(`  Status: ${STATUS_ICONS[report.status] || report.status}`);
  lines.push(`  Duration: ${chalk.dim(`${report.metadata.duration}ms`)}`);
  lines.push("");

  // Summary bar
  const { summary } = report;
  lines.push(chalk.bold("  ─── Summary ────────────────────────────────────────"));
  lines.push("");
  lines.push(`  Total findings: ${summary.totalFindings}`);
  if (summary.criticalCount > 0) lines.push(`    ${chalk.bgRed.white(` ${summary.criticalCount} CRITICAL `)}`);
  if (summary.highCount > 0) lines.push(`    ${chalk.red(`${summary.highCount} High`)}`);
  if (summary.mediumCount > 0) lines.push(`    ${chalk.yellow(`${summary.mediumCount} Medium`)}`);
  if (summary.lowCount > 0) lines.push(`    ${chalk.blue(`${summary.lowCount} Low`)}`);
  if (summary.infoCount > 0) lines.push(`    ${chalk.dim(`${summary.infoCount} Info`)}`);
  lines.push(`  Modules: ${summary.modulesPassed}/${summary.modulesRun} passed`);
  lines.push("");

  // Module results
  lines.push(chalk.bold("  ─── Module Results ─────────────────────────────────"));
  lines.push("");
  for (const moduleResult of report.modules) {
    lines.push(formatModuleResult(moduleResult));
    lines.push("");
  }

  // Detailed findings (skip info)
  const importantFindings = report.findings.filter((f) => f.severity !== "info");
  if (importantFindings.length > 0) {
    lines.push(chalk.bold("  ─── Findings ───────────────────────────────────────"));
    lines.push("");

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    importantFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    for (let i = 0; i < importantFindings.length; i++) {
      lines.push(formatFinding(importantFindings[i], i));
      lines.push("");
    }
  }

  lines.push(chalk.bold("  ─────────────────────────────────────────────────────"));
  lines.push("");

  return lines.join("\n");
}
