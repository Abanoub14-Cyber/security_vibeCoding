"use client";

interface ModuleResult {
  module: string;
  findings: any[];
  score: number;
  duration: number;
  status: "passed" | "failed" | "warning" | "error" | "skipped";
  error?: string;
}

interface ModuleResultsProps {
  modules: ModuleResult[];
}

const MODULE_NAMES: Record<string, string> = {
  "secret-scanner": "Secret Scanner",
  "frontend-checker": "Frontend/API Checker",
  "database-checker": "Database Exposure",
  "agent-checker": "AI Agent Risk",
};

const STATUS_STYLES: Record<string, string> = {
  passed: "bg-green-500/10 text-green-500 border-green-500/30",
  failed: "bg-red-500/10 text-red-500 border-red-500/30",
  warning: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
  error: "bg-red-500/10 text-red-500 border-red-500/30",
  skipped: "bg-gray-500/10 text-gray-500 border-gray-500/30",
};

function getScoreColor(score: number): string {
  if (score >= 90) return "text-green-500";
  if (score >= 75) return "text-green-400";
  if (score >= 60) return "text-yellow-500";
  if (score >= 40) return "text-red-400";
  return "text-red-600";
}

export function ModuleResults({ modules }: ModuleResultsProps) {
  return (
    <div>
      <h3 className="mb-4 text-lg font-semibold text-foreground">Module Results</h3>
      <div className="space-y-3">
        {modules.map((mod) => (
          <div
            key={mod.module}
            className="flex flex-wrap items-center gap-4 rounded-lg border border-border bg-card p-4"
          >
            <span className={`rounded border px-2 py-0.5 text-xs font-bold ${STATUS_STYLES[mod.status]}`}>
              {mod.status.toUpperCase()}
            </span>

            <span className="min-w-[160px] font-medium text-foreground">
              {MODULE_NAMES[mod.module] || mod.module}
            </span>

            <span className={`font-bold ${getScoreColor(mod.score)}`}>
              {mod.score}/100
            </span>

            <span className="text-sm text-muted-foreground">
              {mod.findings.length} finding{mod.findings.length !== 1 ? "s" : ""}
            </span>

            <span className="text-xs text-muted-foreground">{mod.duration}ms</span>

            {mod.error && (
              <span className="w-full text-sm text-red-400">{mod.error}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
