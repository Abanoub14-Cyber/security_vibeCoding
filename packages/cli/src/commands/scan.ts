import { resolve } from "node:path";
import { writeFile } from "node:fs/promises";
import chalk from "chalk";
import ora from "ora";
import { scan } from "@vibecode/scanner";
import type { ScanConfig, ModuleName, ScanReport } from "@vibecode/shared";
import { formatTextReport } from "../utils/formatters.js";
import { generateHtmlReport } from "../utils/html-report.js";

interface ScanOptions {
  modules?: string[];
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  supabaseServiceKey?: string;
  threshold: string;
  format: string;
  output?: string;
  ci?: boolean;
  verbose?: boolean;
}

export async function scanCommand(path: string, options: ScanOptions) {
  const targetPath = resolve(path);

  console.log("");
  console.log(chalk.bold.cyan("  ╔══════════════════════════════════════════╗"));
  console.log(chalk.bold.cyan("  ║   VibeCode Security Gate                ║"));
  console.log(chalk.bold.cyan("  ║   Find the mistakes before attackers do ║"));
  console.log(chalk.bold.cyan("  ╚══════════════════════════════════════════╝"));
  console.log("");
  console.log(chalk.dim(`  Target: ${targetPath}`));
  console.log("");

  // Build scan config
  const modules: ModuleName[] = options.modules
    ? (options.modules as ModuleName[])
    : ["secret-scanner", "frontend-checker", "database-checker", "agent-checker"];

  const config: ScanConfig = {
    target: {
      type: "directory",
      path: targetPath,
    },
    modules,
    threshold: parseInt(options.threshold, 10),
    verbose: options.verbose,
  };

  // Add Supabase config if provided
  if (options.supabaseUrl && options.supabaseAnonKey) {
    config.supabase = {
      projectUrl: options.supabaseUrl,
      anonKey: options.supabaseAnonKey,
      serviceRoleKey: options.supabaseServiceKey,
    };
  }

  const spinner = ora("Running security scan...").start();

  try {
    const report = await scan(config);

    spinner.stop();
    console.log("");

    // Output based on format
    switch (options.format) {
      case "json":
        if (options.output) {
          await writeFile(options.output, JSON.stringify(report, null, 2));
          console.log(chalk.green(`  Report saved to ${options.output}`));
        } else {
          console.log(JSON.stringify(report, null, 2));
        }
        break;

      case "html": {
        const html = generateHtmlReport(report);
        if (options.output) {
          await writeFile(options.output, html);
          console.log(chalk.green(`  HTML report saved to ${options.output}`));
        } else {
          const defaultPath = `vibecode-report-${Date.now()}.html`;
          await writeFile(defaultPath, html);
          console.log(chalk.green(`  HTML report saved to ${defaultPath}`));
        }
        break;
      }

      default:
        console.log(formatTextReport(report));
        break;
    }

    // Also save JSON for future reference if outputting text
    if (options.format === "text" && options.output) {
      await writeFile(options.output, JSON.stringify(report, null, 2));
      console.log(chalk.dim(`  JSON report saved to ${options.output}`));
    }

    // CI mode: exit with error code if threshold not met
    if (options.ci && report.status === "failed") {
      console.log("");
      console.log(chalk.red.bold(`  ✖ Score ${report.overallScore} is below threshold ${options.threshold}. Blocking deploy.`));
      process.exit(1);
    }
  } catch (error) {
    spinner.fail("Scan failed");
    console.error(chalk.red(`  Error: ${error instanceof Error ? error.message : "Unknown error"}`));
    process.exit(1);
  }
}
