"use client";

import { useState } from "react";
import { ScoreCard } from "@/components/score-card";
import { ModuleResults } from "@/components/module-results";
import { FindingsList } from "@/components/findings-list";
import { ScanForm } from "@/components/scan-form";
import { StatsBar } from "@/components/stats-bar";

interface ScanReport {
  id: string;
  timestamp: string;
  target: { type: string; path: string };
  overallScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
  status: "passed" | "failed" | "warning";
  modules: any[];
  findings: any[];
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    modulesRun: number;
    modulesPassed: number;
  };
  metadata: any;
}

export default function DashboardPage() {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleScan(config: { path: string; modules: string[]; supabaseUrl?: string; supabaseAnonKey?: string }) {
    setScanning(true);
    setError(null);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
      const response = await fetch(`${apiUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: { type: "directory", path: config.path },
          modules: config.modules,
          supabase: config.supabaseUrl ? {
            projectUrl: config.supabaseUrl,
            anonKey: config.supabaseAnonKey,
          } : undefined,
        }),
      });

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const data = await response.json();
      setReport(data.report);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      {/* Hero Section */}
      {!report && (
        <div className="mb-12 text-center">
          <h2 className="mb-3 text-3xl font-bold text-foreground">
            Security Scanner for Vibe-Coded Projects
          </h2>
          <p className="mx-auto max-w-2xl text-muted-foreground">
            Scan your Lovable, Bolt, v0, or Cursor project for leaked secrets,
            exposed databases, insecure frontend patterns, and AI agent vulnerabilities.
          </p>
        </div>
      )}

      {/* Scan Form */}
      <div className="mb-8">
        <ScanForm onScan={handleScan} scanning={scanning} />
      </div>

      {/* Error */}
      {error && (
        <div className="mb-8 rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-destructive">
          {error}
        </div>
      )}

      {/* Results */}
      {report && (
        <div className="space-y-8">
          {/* Score */}
          <ScoreCard
            score={report.overallScore}
            grade={report.grade}
            status={report.status}
          />

          {/* Stats */}
          <StatsBar summary={report.summary} />

          {/* Module Results */}
          <ModuleResults modules={report.modules} />

          {/* Findings */}
          <FindingsList findings={report.findings} />
        </div>
      )}

      {/* Empty state */}
      {!report && !scanning && !error && (
        <div className="mt-12 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
          {[
            { title: "Secret Scanner", desc: "Detects leaked API keys, tokens, and credentials in source code and bundles", icon: "K" },
            { title: "Frontend Checker", desc: "Finds client-side API calls, hardcoded secrets, and insecure patterns", icon: "F" },
            { title: "Database Exposure", desc: "Tests Supabase RLS policies by actively probing tables with anon key", icon: "D" },
            { title: "Agent Risk", desc: "Audits AI agent tools, MCP configs, and prompt injection vectors", icon: "A" },
          ].map((module) => (
            <div
              key={module.title}
              className="rounded-xl border border-border bg-card p-6 transition-colors hover:border-primary/50"
            >
              <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary font-bold">
                {module.icon}
              </div>
              <h3 className="mb-2 font-semibold text-foreground">{module.title}</h3>
              <p className="text-sm text-muted-foreground">{module.desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
