import { v4 as uuid } from "uuid";
import type {
  ScanConfig,
  ScanReport,
  ModuleResult,
  ModuleName,
} from "@vibecode/shared";
import { SCANNER_VERSION } from "@vibecode/shared";
import { runSecretScanner } from "./modules/secret-scanner.js";
import { runFrontendChecker } from "./modules/frontend-checker.js";
import { runDatabaseChecker } from "./modules/database-checker.js";
import { runAgentChecker } from "./modules/agent-checker.js";
import {
  calculateOverallScore,
  calculateGrade,
  calculateSummary,
  determineStatus,
} from "./scoring.js";

export { runSecretScanner } from "./modules/secret-scanner.js";
export { runFrontendChecker } from "./modules/frontend-checker.js";
export { runDatabaseChecker } from "./modules/database-checker.js";
export { runAgentChecker } from "./modules/agent-checker.js";
export { calculateOverallScore, calculateGrade, calculateSummary, determineStatus } from "./scoring.js";

const MODULE_RUNNERS: Record<ModuleName, (config: ScanConfig) => Promise<ModuleResult>> = {
  "secret-scanner": runSecretScanner,
  "frontend-checker": runFrontendChecker,
  "database-checker": runDatabaseChecker,
  "agent-checker": runAgentChecker,
};

export async function scan(config: ScanConfig): Promise<ScanReport> {
  const start = Date.now();

  const modulesToRun = config.modules.length > 0
    ? config.modules
    : (Object.keys(MODULE_RUNNERS) as ModuleName[]);

  // Run all selected modules in parallel
  const moduleResults = await Promise.all(
    modulesToRun.map(async (moduleName) => {
      const runner = MODULE_RUNNERS[moduleName];
      if (!runner) {
        return {
          module: moduleName,
          findings: [],
          score: 0,
          duration: 0,
          status: "error" as const,
          error: `Unknown module: ${moduleName}`,
        };
      }
      return runner(config);
    })
  );

  // Aggregate findings
  const allFindings = moduleResults.flatMap((r) => r.findings);

  // Calculate scores
  const overallScore = calculateOverallScore(moduleResults);
  const grade = calculateGrade(overallScore);
  const status = determineStatus(overallScore, config.threshold);

  // Build summary
  const summary = calculateSummary(allFindings);
  summary.modulesRun = moduleResults.length;
  summary.modulesPassed = moduleResults.filter((r) => r.status === "passed").length;

  return {
    id: uuid(),
    timestamp: new Date().toISOString(),
    target: config.target,
    overallScore,
    grade,
    status,
    modules: moduleResults,
    findings: allFindings,
    summary,
    metadata: {
      scannerVersion: SCANNER_VERSION,
      nodeVersion: process.version,
      platform: process.platform,
      duration: Date.now() - start,
    },
  };
}
