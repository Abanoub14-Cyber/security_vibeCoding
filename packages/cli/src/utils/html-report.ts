import type { ScanReport, Finding, ModuleResult } from "@vibecode/shared";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
  info: "#6b7280",
};

const GRADE_COLORS: Record<string, string> = {
  A: "#16a34a",
  B: "#22c55e",
  C: "#eab308",
  D: "#ef4444",
  F: "#dc2626",
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderFinding(finding: Finding, index: number): string {
  const color = SEVERITY_COLORS[finding.severity] || "#6b7280";
  const location = finding.location.file
    ? `${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`
    : finding.location.table
      ? `Table: ${finding.location.table}`
      : "";

  return `
    <div class="finding" style="border-left: 4px solid ${color};">
      <div class="finding-header">
        <span class="severity-badge" style="background: ${color};">${finding.severity.toUpperCase()}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
        ${finding.verified ? '<span class="verified-badge">VERIFIED</span>' : ""}
      </div>
      ${location ? `<div class="finding-location">${escapeHtml(location)}</div>` : ""}
      <p class="finding-description">${escapeHtml(finding.description)}</p>
      ${finding.evidence ? `<div class="finding-evidence"><strong>Evidence:</strong> <code>${escapeHtml(finding.evidence)}</code></div>` : ""}
      <div class="finding-remediation"><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</div>
      ${finding.tags.length > 0 ? `<div class="finding-tags">${finding.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
    </div>
  `;
}

function renderModuleResult(result: ModuleResult): string {
  const names: Record<string, string> = {
    "secret-scanner": "Secret Scanner",
    "frontend-checker": "Frontend/API Checker",
    "database-checker": "Database Exposure",
    "agent-checker": "AI Agent Risk",
  };

  const statusColors: Record<string, string> = {
    passed: "#16a34a",
    failed: "#dc2626",
    warning: "#ca8a04",
    error: "#dc2626",
    skipped: "#6b7280",
  };

  return `
    <div class="module-result">
      <div class="module-header">
        <span class="module-status" style="background: ${statusColors[result.status] || "#6b7280"};">${result.status.toUpperCase()}</span>
        <span class="module-name">${names[result.module] || result.module}</span>
        <span class="module-score">Score: ${result.score}/100</span>
        <span class="module-duration">${result.duration}ms</span>
      </div>
      ${result.findings.length > 0 ? `<div class="module-findings-count">${result.findings.length} finding(s)</div>` : ""}
    </div>
  `;
}

export function generateHtmlReport(report: ScanReport): string {
  const gradeColor = GRADE_COLORS[report.grade] || "#6b7280";

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedFindings = [...report.findings]
    .filter((f) => f.severity !== "info")
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeCode Security Report — ${escapeHtml(report.target.path)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 960px; margin: 0 auto; padding: 2rem; }

    .header { text-align: center; margin-bottom: 3rem; padding: 2rem; background: linear-gradient(135deg, #1e293b, #334155); border-radius: 16px; border: 1px solid #475569; }
    .header h1 { font-size: 1.8rem; color: #38bdf8; margin-bottom: 0.5rem; }
    .header .tagline { color: #94a3b8; font-size: 0.9rem; }

    .score-card { display: flex; justify-content: center; align-items: center; gap: 2rem; margin: 2rem 0; }
    .score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; background: #1e293b; border: 4px solid ${gradeColor}; }
    .score-number { font-size: 2.5rem; font-weight: 800; color: ${gradeColor}; }
    .score-label { font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; }
    .grade-badge { font-size: 3rem; font-weight: 900; color: ${gradeColor}; }

    .status-bar { display: flex; justify-content: center; gap: 1.5rem; margin: 1.5rem 0; flex-wrap: wrap; }
    .status-item { padding: 0.5rem 1rem; background: #1e293b; border-radius: 8px; font-size: 0.85rem; }

    .section { margin: 2rem 0; }
    .section-title { font-size: 1.2rem; font-weight: 700; color: #38bdf8; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }

    .module-result { background: #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .module-status { padding: 0.25rem 0.5rem; border-radius: 4px; color: white; font-size: 0.7rem; font-weight: 700; }
    .module-name { font-weight: 600; flex: 1; }
    .module-score { color: #94a3b8; }
    .module-duration { color: #64748b; font-size: 0.8rem; }
    .module-findings-count { color: #94a3b8; font-size: 0.8rem; width: 100%; margin-top: 0.25rem; }

    .finding { background: #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
    .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
    .severity-badge { padding: 0.2rem 0.5rem; border-radius: 4px; color: white; font-size: 0.7rem; font-weight: 700; }
    .finding-title { font-weight: 600; }
    .verified-badge { background: #dc2626; color: white; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; }
    .finding-location { color: #64748b; font-size: 0.8rem; font-family: monospace; margin-bottom: 0.5rem; }
    .finding-description { color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.5rem; }
    .finding-evidence { background: #0f172a; padding: 0.5rem; border-radius: 4px; font-size: 0.8rem; margin-bottom: 0.5rem; }
    .finding-evidence code { color: #fbbf24; }
    .finding-remediation { font-size: 0.85rem; color: #67e8f9; }
    .finding-tags { display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap; }
    .tag { background: #334155; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; color: #94a3b8; }

    .footer { text-align: center; margin-top: 3rem; padding: 1.5rem; color: #64748b; font-size: 0.8rem; border-top: 1px solid #334155; }

    @media print {
      body { background: white; color: #1e293b; }
      .header { background: #f8fafc; border-color: #e2e8f0; }
      .module-result, .finding { background: #f8fafc; }
      .finding-evidence { background: #f1f5f9; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>VibeCode Security Gate</h1>
      <p class="tagline">Find the mistakes vibe coding introduces — before attackers do.</p>
    </div>

    <div class="score-card">
      <div class="score-circle">
        <span class="score-number">${report.overallScore}</span>
        <span class="score-label">Score</span>
      </div>
      <div class="grade-badge">${report.grade}</div>
    </div>

    <div class="status-bar">
      <div class="status-item"><strong>${report.summary.totalFindings}</strong> findings</div>
      <div class="status-item" style="color: #dc2626;"><strong>${report.summary.criticalCount}</strong> critical</div>
      <div class="status-item" style="color: #ea580c;"><strong>${report.summary.highCount}</strong> high</div>
      <div class="status-item" style="color: #ca8a04;"><strong>${report.summary.mediumCount}</strong> medium</div>
      <div class="status-item"><strong>${report.summary.modulesPassed}/${report.summary.modulesRun}</strong> modules passed</div>
    </div>

    <div class="section">
      <h2 class="section-title">Module Results</h2>
      ${report.modules.map(renderModuleResult).join("")}
    </div>

    ${sortedFindings.length > 0 ? `
    <div class="section">
      <h2 class="section-title">Findings (${sortedFindings.length})</h2>
      ${sortedFindings.map((f, i) => renderFinding(f, i)).join("")}
    </div>
    ` : `
    <div class="section">
      <h2 class="section-title">No security issues found</h2>
      <p style="color: #22c55e;">All checks passed. Your project looks secure!</p>
    </div>
    `}

    <div class="footer">
      <p>Generated by VibeCode Security Gate v${report.metadata.scannerVersion}</p>
      <p>Scan ID: ${report.id} | ${new Date(report.timestamp).toLocaleString()}</p>
      <p>Duration: ${report.metadata.duration}ms | Platform: ${report.metadata.platform}</p>
    </div>
  </div>
</body>
</html>`;
}
