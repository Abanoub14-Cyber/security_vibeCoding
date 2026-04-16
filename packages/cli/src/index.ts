#!/usr/bin/env node

import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { reportCommand } from "./commands/report.js";
import { SCANNER_VERSION } from "@vibecode/shared";

const program = new Command();

program
  .name("vibecode-scan")
  .description("VibeCode Security Gate — Find the mistakes vibe coding introduces before attackers do.")
  .version(SCANNER_VERSION);

program
  .command("scan")
  .description("Scan a project for security vulnerabilities")
  .argument("[path]", "Path to the project directory", ".")
  .option("-m, --modules <modules...>", "Modules to run (secret-scanner, frontend-checker, database-checker, agent-checker)")
  .option("--supabase-url <url>", "Supabase project URL for active database probing")
  .option("--supabase-anon-key <key>", "Supabase anon key for active database probing")
  .option("--supabase-service-key <key>", "Supabase service role key (for RLS policy enumeration)")
  .option("-t, --threshold <score>", "Minimum passing score (0-100)", "70")
  .option("-f, --format <format>", "Output format (text, json, html)", "text")
  .option("-o, --output <file>", "Write report to file")
  .option("--ci", "CI mode: exit with non-zero code if threshold not met")
  .option("-v, --verbose", "Verbose output")
  .action(scanCommand);

program
  .command("report")
  .description("Generate a report from a previous scan result")
  .argument("<scan-file>", "Path to scan result JSON file")
  .option("-f, --format <format>", "Output format (html, pdf, json)", "html")
  .option("-o, --output <file>", "Output file path")
  .action(reportCommand);

program.parse();
