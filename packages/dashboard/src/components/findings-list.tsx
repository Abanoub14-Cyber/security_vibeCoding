"use client";

import { useState } from "react";

interface Finding {
  id: string;
  module: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  location: { file?: string; line?: number; table?: string; url?: string };
  remediation: string;
  evidence?: string;
  verified?: boolean;
  tags: string[];
}

interface FindingsListProps {
  findings: Finding[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-white",
  low: "bg-blue-600 text-white",
  info: "bg-gray-600 text-white",
};

const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-l-red-600",
  high: "border-l-orange-600",
  medium: "border-l-yellow-600",
  low: "border-l-blue-600",
  info: "border-l-gray-600",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

export function FindingsList({ findings }: FindingsListProps) {
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = findings
    .filter((f) => filter === "all" || f.severity === filter)
    .filter((f) => f.severity !== "info")
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground">
          Findings ({filtered.length})
        </h3>
        <div className="flex gap-2">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`rounded-lg px-3 py-1 text-xs font-medium transition-colors ${
                filter === sev
                  ? "bg-primary text-primary-foreground"
                  : "bg-card text-muted-foreground hover:text-foreground"
              }`}
            >
              {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-muted-foreground">
          {filter === "all"
            ? "No security issues found!"
            : `No ${filter} severity findings.`}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((finding) => {
            const expanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className={`rounded-lg border border-border border-l-4 bg-card ${SEVERITY_BORDER[finding.severity]}`}
              >
                <button
                  onClick={() => setExpandedId(expanded ? null : finding.id)}
                  className="flex w-full items-start gap-3 p-4 text-left"
                >
                  <span className={`mt-0.5 shrink-0 rounded px-2 py-0.5 text-xs font-bold ${SEVERITY_COLORS[finding.severity]}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-foreground">{finding.title}</span>
                      {finding.verified && (
                        <span className="rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">
                          VERIFIED
                        </span>
                      )}
                    </div>
                    {finding.location.file && (
                      <span className="text-xs font-mono text-muted-foreground">
                        {finding.location.file}
                        {finding.location.line ? `:${finding.location.line}` : ""}
                      </span>
                    )}
                    {finding.location.table && (
                      <span className="text-xs font-mono text-muted-foreground">
                        Table: {finding.location.table}
                      </span>
                    )}
                  </div>
                  <span className="text-muted-foreground">{expanded ? "-" : "+"}</span>
                </button>

                {expanded && (
                  <div className="border-t border-border px-4 pb-4 pt-3 space-y-3">
                    <p className="text-sm text-muted-foreground">{finding.description}</p>

                    {finding.evidence && (
                      <div className="rounded bg-background p-3">
                        <span className="text-xs font-semibold text-muted-foreground">Evidence:</span>
                        <code className="mt-1 block text-sm text-warning">{finding.evidence}</code>
                      </div>
                    )}

                    <div>
                      <span className="text-xs font-semibold text-accent">Remediation:</span>
                      <p className="mt-1 text-sm text-accent/80 whitespace-pre-line">{finding.remediation}</p>
                    </div>

                    {finding.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {finding.tags.map((tag) => (
                          <span key={tag} className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
