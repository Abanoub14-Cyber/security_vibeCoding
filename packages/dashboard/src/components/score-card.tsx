"use client";

interface ScoreCardProps {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  status: "passed" | "failed" | "warning";
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-500 border-green-500",
  B: "text-green-400 border-green-400",
  C: "text-yellow-500 border-yellow-500",
  D: "text-red-400 border-red-400",
  F: "text-red-600 border-red-600",
};

const STATUS_LABELS: Record<string, { text: string; color: string }> = {
  passed: { text: "PASSED", color: "bg-green-500/10 text-green-500 border-green-500/30" },
  warning: { text: "WARNING", color: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30" },
  failed: { text: "FAILED", color: "bg-red-500/10 text-red-500 border-red-500/30" },
};

export function ScoreCard({ score, grade, status }: ScoreCardProps) {
  const gradeColor = GRADE_COLORS[grade] || GRADE_COLORS.F;
  const statusInfo = STATUS_LABELS[status] || STATUS_LABELS.failed;

  return (
    <div className="flex flex-col items-center gap-6 rounded-xl border border-border bg-card p-8 md:flex-row md:justify-center">
      {/* Score circle */}
      <div className={`flex h-32 w-32 flex-col items-center justify-center rounded-full border-4 ${gradeColor}`}>
        <span className={`text-4xl font-black ${gradeColor.split(" ")[0]}`}>{score}</span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>

      <div className="text-center md:text-left">
        {/* Grade */}
        <div className={`mb-2 text-6xl font-black ${gradeColor.split(" ")[0]}`}>{grade}</div>

        {/* Status badge */}
        <div className={`inline-block rounded-lg border px-3 py-1 text-sm font-semibold ${statusInfo.color}`}>
          {statusInfo.text}
        </div>
      </div>
    </div>
  );
}
