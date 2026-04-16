import { readFile, writeFile } from "node:fs/promises";
import chalk from "chalk";
import type { ScanReport } from "@vibecode/shared";
import { generateHtmlReport } from "../utils/html-report.js";

interface ReportOptions {
  format: string;
  output?: string;
}

export async function reportCommand(scanFile: string, options: ReportOptions) {
  try {
    const data = await readFile(scanFile, "utf-8");
    const report: ScanReport = JSON.parse(data);

    switch (options.format) {
      case "html": {
        const html = generateHtmlReport(report);
        const outputPath = options.output || `vibecode-report-${Date.now()}.html`;
        await writeFile(outputPath, html);
        console.log(chalk.green(`HTML report saved to ${outputPath}`));
        break;
      }
      case "json": {
        const outputPath = options.output || `vibecode-report-${Date.now()}.json`;
        await writeFile(outputPath, JSON.stringify(report, null, 2));
        console.log(chalk.green(`JSON report saved to ${outputPath}`));
        break;
      }
      default:
        console.log(chalk.red(`Unsupported format: ${options.format}`));
    }
  } catch (error) {
    console.error(chalk.red(`Error: ${error instanceof Error ? error.message : "Failed to read scan file"}`));
    process.exit(1);
  }
}
