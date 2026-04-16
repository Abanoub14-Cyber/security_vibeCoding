import * as core from "@actions/core";
import * as github from "@actions/github";
import { scan } from "@vibecode/scanner";
import type { ModuleName, ScanConfig } from "@vibecode/shared";

async function run() {
  try {
    const path = core.getInput("path") || ".";
    const modulesInput = core.getInput("modules");
    const threshold = parseInt(core.getInput("threshold") || "70", 10);
    const supabaseUrl = core.getInput("supabase-url");
    const supabaseAnonKey = core.getInput("supabase-anon-key");
    const failOnFindings = core.getInput("fail-on-findings") === "true";

    const modules = modulesInput
      ? (modulesInput.split(",").map((m) => m.trim()) as ModuleName[])
      : (["secret-scanner", "frontend-checker", "database-checker", "agent-checker"] as ModuleName[]);

    core.info("VibeCode Security Gate - Scanning...");
    core.info(`Target: ${path}`);
    core.info(`Modules: ${modules.join(", ")}`);
    core.info(`Threshold: ${threshold}`);

    const config: ScanConfig = {
      target: { type: "directory", path },
      modules,
      threshold,
    };

    if (supabaseUrl && supabaseAnonKey) {
      config.supabase = {
        projectUrl: supabaseUrl,
        anonKey: supabaseAnonKey,
      };
    }

    const report = await scan(config);

    // Set outputs
    core.setOutput("score", report.overallScore.toString());
    core.setOutput("grade", report.grade);
    core.setOutput("findings-count", report.summary.totalFindings.toString());
    core.setOutput("critical-count", report.summary.criticalCount.toString());
    core.setOutput("report-json", JSON.stringify(report));
    core.setOutput("status", report.status);

    // Log results
    core.info("");
    core.info(`Score: ${report.overallScore}/100 (Grade: ${report.grade})`);
    core.info(`Findings: ${report.summary.totalFindings} total`);
    core.info(`  Critical: ${report.summary.criticalCount}`);
    core.info(`  High: ${report.summary.highCount}`);
    core.info(`  Medium: ${report.summary.mediumCount}`);
    core.info(`  Low: ${report.summary.lowCount}`);

    for (const moduleResult of report.modules) {
      const icon = moduleResult.status === "passed" ? "+" : moduleResult.status === "failed" ? "x" : "!";
      core.info(`  [${icon}] ${moduleResult.module}: ${moduleResult.score}/100 (${moduleResult.findings.length} findings)`);
    }

    // Log critical findings as annotations
    for (const finding of report.findings) {
      if (finding.severity === "critical" || finding.severity === "high") {
        const annotation = {
          title: finding.title,
          file: finding.location.file,
          startLine: finding.location.line,
        };

        if (finding.severity === "critical") {
          core.error(finding.description, annotation);
        } else {
          core.warning(finding.description, annotation);
        }
      }
    }

    // Determine if we should fail
    if (failOnFindings && report.status === "failed") {
      core.setFailed(
        `Security score ${report.overallScore} is below threshold ${threshold}. ` +
        `Found ${report.summary.criticalCount} critical and ${report.summary.highCount} high severity issues.`
      );
    } else if (report.summary.criticalCount > 0) {
      core.warning(
        `Found ${report.summary.criticalCount} critical findings. Review recommended before deploy.`
      );
    }

    // Add PR comment if this is a pull request
    if (github.context.payload.pull_request) {
      core.info("Pull request detected — findings logged as annotations above.");
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : "VibeCode scan failed");
  }
}

run();
