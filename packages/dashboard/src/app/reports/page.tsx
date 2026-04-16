"use client";

export default function ReportsPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <h2 className="mb-6 text-2xl font-bold text-foreground">Scan Reports</h2>

      <div className="rounded-xl border border-border bg-card p-12 text-center">
        <div className="mb-4 text-4xl">📋</div>
        <h3 className="mb-2 text-lg font-semibold text-foreground">No reports yet</h3>
        <p className="mb-6 text-muted-foreground">
          Run your first scan to generate a security report. Reports are saved
          automatically and can be exported as HTML or PDF.
        </p>
        <a
          href="/scan"
          className="inline-block rounded-lg bg-primary px-6 py-2.5 font-semibold text-primary-foreground hover:opacity-90 transition-opacity"
        >
          Run a Scan
        </a>
      </div>
    </div>
  );
}
