import type { Finding, ModuleResult, ScanReport, ScanSummary } from "@vibecode/shared";
import { SEVERITY_WEIGHTS, MODULE_WEIGHTS, GRADE_THRESHOLDS } from "@vibecode/shared";

/**
 * Risk Scoring Engine
 *
 * Calculates a 0-100 security score based on:
 * - Severity of findings (critical=25, high=15, medium=8, low=3)
 * - Module weights (secrets=30%, frontend=25%, database=30%, agents=15%)
 * - Exploitability (verified findings get 1.5x weight)
 * - Data sensitivity (PII-related findings get 1.3x weight)
 */

function calculateModuleScore(result: ModuleResult): number {
  if (result.status === "error" || result.status === "skipped") {
    return result.status === "skipped" ? 100 : 50;
  }

  let deductions = 0;

  for (const finding of result.findings) {
    let weight = SEVERITY_WEIGHTS[finding.severity];

    // Verified findings are more impactful
    if (finding.verified) {
      weight *= 1.5;
    }

    // PII-related findings get extra weight
    if (finding.tags.includes("pii") || finding.tags.includes("data-exposure")) {
      weight *= 1.3;
    }

    deductions += weight;
  }

  return Math.max(0, Math.round(100 - deductions));
}

export function calculateOverallScore(modules: ModuleResult[]): number {
  let weightedSum = 0;
  let totalWeight = 0;

  for (const result of modules) {
    const moduleWeight = MODULE_WEIGHTS[result.module] || 0.25;
    const moduleScore = calculateModuleScore(result);
    weightedSum += moduleScore * moduleWeight;
    totalWeight += moduleWeight;
  }

  if (totalWeight === 0) return 100;

  return Math.round(weightedSum / totalWeight);
}

export function calculateGrade(score: number): ScanReport["grade"] {
  if (score >= GRADE_THRESHOLDS.A) return "A";
  if (score >= GRADE_THRESHOLDS.B) return "B";
  if (score >= GRADE_THRESHOLDS.C) return "C";
  if (score >= GRADE_THRESHOLDS.D) return "D";
  return "F";
}

export function calculateSummary(findings: Finding[]): ScanSummary {
  return {
    totalFindings: findings.length,
    criticalCount: findings.filter((f) => f.severity === "critical").length,
    highCount: findings.filter((f) => f.severity === "high").length,
    mediumCount: findings.filter((f) => f.severity === "medium").length,
    lowCount: findings.filter((f) => f.severity === "low").length,
    infoCount: findings.filter((f) => f.severity === "info").length,
    modulesRun: 0, // Set by caller
    modulesPassed: 0, // Set by caller
  };
}

export function determineStatus(
  score: number,
  threshold: number = 70
): ScanReport["status"] {
  if (score >= threshold) return "passed";
  if (score >= threshold - 20) return "warning";
  return "failed";
}
