"use client";

import { useState } from "react";
import { ScanForm } from "@/components/scan-form";
import { ScoreCard } from "@/components/score-card";
import { ModuleResults } from "@/components/module-results";
import { FindingsList } from "@/components/findings-list";
import { StatsBar } from "@/components/stats-bar";

export default function ScanPage() {
  const [report, setReport] = useState<any>(null);
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

      if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`);
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
      <h2 className="mb-6 text-2xl font-bold text-foreground">New Security Scan</h2>

      <ScanForm onScan={handleScan} scanning={scanning} />

      {error && (
        <div className="mt-6 rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-destructive">
          {error}
        </div>
      )}

      {report && (
        <div className="mt-8 space-y-8">
          <ScoreCard score={report.overallScore} grade={report.grade} status={report.status} />
          <StatsBar summary={report.summary} />
          <ModuleResults modules={report.modules} />
          <FindingsList findings={report.findings} />
        </div>
      )}
    </div>
  );
}
