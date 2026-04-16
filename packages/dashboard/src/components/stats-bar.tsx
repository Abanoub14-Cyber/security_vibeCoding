"use client";

interface StatsBarProps {
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
}

export function StatsBar({ summary }: StatsBarProps) {
  const stats = [
    { label: "Total", value: summary.totalFindings, color: "text-foreground" },
    { label: "Critical", value: summary.criticalCount, color: "text-red-600" },
    { label: "High", value: summary.highCount, color: "text-orange-500" },
    { label: "Medium", value: summary.mediumCount, color: "text-yellow-500" },
    { label: "Low", value: summary.lowCount, color: "text-blue-500" },
    { label: "Modules Passed", value: `${summary.modulesPassed}/${summary.modulesRun}`, color: "text-green-500" },
  ];

  return (
    <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
      {stats.map((stat) => (
        <div key={stat.label} className="rounded-lg border border-border bg-card p-4 text-center">
          <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
          <div className="text-xs text-muted-foreground">{stat.label}</div>
        </div>
      ))}
    </div>
  );
}
