"use client";

import { useState } from "react";

interface ScanFormProps {
  onScan: (config: {
    path: string;
    modules: string[];
    supabaseUrl?: string;
    supabaseAnonKey?: string;
  }) => void;
  scanning: boolean;
}

const ALL_MODULES = [
  { id: "secret-scanner", label: "Secret Scanner", desc: "Detect leaked credentials" },
  { id: "frontend-checker", label: "Frontend Checker", desc: "Client-side security" },
  { id: "database-checker", label: "Database Exposure", desc: "RLS & data access" },
  { id: "agent-checker", label: "Agent Risk", desc: "AI agent security" },
];

export function ScanForm({ onScan, scanning }: ScanFormProps) {
  const [path, setPath] = useState("");
  const [modules, setModules] = useState<string[]>(ALL_MODULES.map((m) => m.id));
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [supabaseUrl, setSupabaseUrl] = useState("");
  const [supabaseAnonKey, setSupabaseAnonKey] = useState("");

  function toggleModule(id: string) {
    setModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onScan({
      path: path || ".",
      modules,
      supabaseUrl: supabaseUrl || undefined,
      supabaseAnonKey: supabaseAnonKey || undefined,
    });
  }

  return (
    <form onSubmit={handleSubmit} className="rounded-xl border border-border bg-card p-6">
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-foreground">
          Project Path or URL
        </label>
        <input
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="/path/to/project or https://github.com/user/repo"
          className="w-full rounded-lg border border-border bg-background px-4 py-2.5 text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>

      {/* Module selection */}
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-foreground">Modules</label>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {ALL_MODULES.map((mod) => (
            <button
              key={mod.id}
              type="button"
              onClick={() => toggleModule(mod.id)}
              className={`rounded-lg border px-3 py-2 text-left text-sm transition-colors ${
                modules.includes(mod.id)
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border bg-background text-muted-foreground hover:border-primary/50"
              }`}
            >
              <div className="font-medium">{mod.label}</div>
              <div className="text-xs opacity-70">{mod.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Advanced options */}
      <div className="mb-4">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          {showAdvanced ? "Hide" : "Show"} advanced options
        </button>

        {showAdvanced && (
          <div className="mt-3 space-y-3 rounded-lg border border-border bg-background p-4">
            <div>
              <label className="mb-1 block text-sm text-muted-foreground">
                Supabase Project URL
              </label>
              <input
                type="text"
                value={supabaseUrl}
                onChange={(e) => setSupabaseUrl(e.target.value)}
                placeholder="https://xyz.supabase.co"
                className="w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-muted-foreground">
                Supabase Anon Key
              </label>
              <input
                type="password"
                value={supabaseAnonKey}
                onChange={(e) => setSupabaseAnonKey(e.target.value)}
                placeholder="eyJhbGci..."
                className="w-full rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              />
            </div>
          </div>
        )}
      </div>

      {/* Submit */}
      <button
        type="submit"
        disabled={scanning}
        className="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {scanning ? (
          <span className="flex items-center justify-center gap-2">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
            Scanning...
          </span>
        ) : (
          "Run Security Scan"
        )}
      </button>
    </form>
  );
}
