import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { v4 as uuid } from "uuid";
import type { Finding, ModuleResult, ScanConfig, SupabaseConfig } from "@vibecode/shared";
import { COMMON_TABLES } from "@vibecode/shared";

interface SupabaseRLSPolicy {
  table: string;
  policyName: string;
  command: string;
  definition: string;
  enabled: boolean;
}

interface TableProbeResult {
  table: string;
  accessible: boolean;
  rowCount?: number;
  sampleColumns?: string[];
  error?: string;
}

async function fetchSupabaseRLS(config: SupabaseConfig): Promise<{ policies: SupabaseRLSPolicy[]; tables: string[] }> {
  // Use the Supabase Management API or direct database query
  const headers: Record<string, string> = {
    "apikey": config.anonKey,
    "Authorization": `Bearer ${config.serviceRoleKey || config.anonKey}`,
    "Content-Type": "application/json",
  };

  try {
    // Query pg_policies through the REST API using RPC
    const response = await fetch(`${config.projectUrl}/rest/v1/rpc/get_rls_policies`, {
      method: "POST",
      headers,
    });

    if (response.ok) {
      const data = await response.json();
      return { policies: data, tables: data.map((p: any) => p.table) };
    }

    // Fallback: try to list tables through PostgREST
    const tablesResponse = await fetch(`${config.projectUrl}/rest/v1/`, {
      headers: { apikey: config.anonKey },
    });

    if (tablesResponse.ok) {
      // PostgREST returns OpenAPI spec with table info
      const spec = await tablesResponse.json();
      const tables = Object.keys(spec.definitions || {});
      return { policies: [], tables };
    }

    return { policies: [], tables: [] };
  } catch {
    return { policies: [], tables: [] };
  }
}

async function probeTable(
  projectUrl: string,
  anonKey: string,
  tableName: string
): Promise<TableProbeResult> {
  try {
    const response = await fetch(
      `${projectUrl}/rest/v1/${tableName}?select=*&limit=5`,
      {
        headers: {
          apikey: anonKey,
          Authorization: `Bearer ${anonKey}`,
          "Content-Type": "application/json",
          Prefer: "count=exact",
        },
      }
    );

    if (response.status === 200) {
      const data = await response.json();
      const contentRange = response.headers.get("content-range");
      const totalMatch = contentRange?.match(/\/(\d+)/);
      const rowCount = totalMatch ? parseInt(totalMatch[1], 10) : data.length;

      if (data.length > 0) {
        return {
          table: tableName,
          accessible: true,
          rowCount,
          sampleColumns: Object.keys(data[0]),
        };
      }

      return {
        table: tableName,
        accessible: true,
        rowCount: 0,
        sampleColumns: [],
      };
    }

    if (response.status === 401 || response.status === 403) {
      return { table: tableName, accessible: false };
    }

    // 404 = table doesn't exist (not exposed via PostgREST)
    return { table: tableName, accessible: false, error: `HTTP ${response.status}` };
  } catch (error) {
    return {
      table: tableName,
      accessible: false,
      error: error instanceof Error ? error.message : "Network error",
    };
  }
}

async function probeWriteAccess(
  projectUrl: string,
  anonKey: string,
  tableName: string
): Promise<{ canInsert: boolean; canUpdate: boolean; canDelete: boolean }> {
  const headers = {
    apikey: anonKey,
    Authorization: `Bearer ${anonKey}`,
    "Content-Type": "application/json",
    Prefer: "return=minimal",
  };

  // Test INSERT with a dry-run (will fail on constraint but reveals if RLS blocks it)
  let canInsert = false;
  try {
    const res = await fetch(`${projectUrl}/rest/v1/${tableName}`, {
      method: "POST",
      headers: { ...headers, Prefer: "return=minimal,resolution=ignore-duplicates" },
      body: JSON.stringify({ _probe: true }),
    });
    // 403 = RLS blocked, 201/409/400 = RLS allowed (constraint error is fine)
    canInsert = res.status !== 403 && res.status !== 401;
  } catch { /* network error */ }

  // Test DELETE
  let canDelete = false;
  try {
    const res = await fetch(`${projectUrl}/rest/v1/${tableName}?_probe=eq.true`, {
      method: "DELETE",
      headers,
    });
    canDelete = res.status !== 403 && res.status !== 401;
  } catch { /* network error */ }

  return { canInsert, canUpdate: canInsert, canDelete };
}

async function checkSupabaseExposure(config: SupabaseConfig): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Step 1: Probe common tables with anon key
  const probeTables = COMMON_TABLES;
  const probeResults = await Promise.all(
    probeTables.map((table) => probeTable(config.projectUrl, config.anonKey, table))
  );

  for (const result of probeResults) {
    if (result.accessible && result.rowCount !== undefined && result.rowCount > 0) {
      const sensitiveColumns = (result.sampleColumns || []).filter((col) =>
        /email|phone|password|hash|token|secret|ssn|address|card|credit|cvv|dob|birth/i.test(col)
      );

      const severity = sensitiveColumns.length > 0 ? "critical" as const : "high" as const;

      findings.push({
        id: uuid(),
        module: "database-checker",
        severity,
        title: `Table "${result.table}" is publicly readable (${result.rowCount} rows)`,
        description: `The "${result.table}" table returned ${result.rowCount} rows using only the anon key. ${
          sensitiveColumns.length > 0
            ? `Contains sensitive columns: ${sensitiveColumns.join(", ")}`
            : "No obviously sensitive column names, but data may still be confidential."
        }`,
        location: { table: result.table },
        remediation: `Enable Row Level Security on the "${result.table}" table and add appropriate policies:\n\nALTER TABLE ${result.table} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Users can only see own data" ON ${result.table} FOR SELECT USING (auth.uid() = user_id);`,
        evidence: `curl "${config.projectUrl}/rest/v1/${result.table}?select=*&limit=1" -H "apikey: ${config.anonKey.substring(0, 20)}..."  →  ${result.rowCount} rows returned`,
        verified: true,
        tags: ["supabase", "rls-missing", "data-exposure", ...(sensitiveColumns.length > 0 ? ["pii"] : [])],
      });

      // Also check write access on exposed tables
      const writeAccess = await probeWriteAccess(config.projectUrl, config.anonKey, result.table);
      if (writeAccess.canInsert || writeAccess.canDelete) {
        findings.push({
          id: uuid(),
          module: "database-checker",
          severity: "critical",
          title: `Table "${result.table}" allows unauthorized writes`,
          description: `The "${result.table}" table allows ${[
            writeAccess.canInsert && "INSERT",
            writeAccess.canUpdate && "UPDATE",
            writeAccess.canDelete && "DELETE",
          ].filter(Boolean).join("/")} operations with just the anon key. An attacker could modify or delete data.`,
          location: { table: result.table },
          remediation: `Add restrictive RLS policies for write operations:\n\nCREATE POLICY "Only authenticated users can insert" ON ${result.table} FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);\nCREATE POLICY "Users can only update own data" ON ${result.table} FOR UPDATE USING (auth.uid() = user_id);`,
          verified: true,
          tags: ["supabase", "rls-missing", "write-access"],
        });
      }
    } else if (result.accessible && result.rowCount === 0) {
      findings.push({
        id: uuid(),
        module: "database-checker",
        severity: "medium",
        title: `Table "${result.table}" is publicly accessible (currently empty)`,
        description: `The "${result.table}" table is accessible with the anon key but contains no data. Once data is added, it will be publicly readable without RLS policies.`,
        location: { table: result.table },
        remediation: `Enable RLS before adding data:\n\nALTER TABLE ${result.table} ENABLE ROW LEVEL SECURITY;`,
        tags: ["supabase", "rls-missing", "preemptive"],
      });
    }
  }

  return findings;
}

async function checkLocalSupabaseConfig(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check for service_role key in client code
  const configFiles = [
    "supabase/config.toml",
    ".env",
    ".env.local",
    ".env.production",
    "src/lib/supabase.ts",
    "src/lib/supabaseClient.ts",
    "src/utils/supabase.ts",
    "lib/supabase.ts",
    "src/integrations/supabase/client.ts",
  ];

  for (const configFile of configFiles) {
    try {
      const content = await readFile(join(targetPath, configFile), "utf-8");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for service_role key usage in client
        if (/service[_-]?role/i.test(line) && /eyJhbGci/i.test(line)) {
          findings.push({
            id: uuid(),
            module: "database-checker",
            severity: "critical",
            title: "Supabase service_role key in client code",
            description: "The Supabase service_role key bypasses all RLS policies. If exposed client-side, any user can access ALL data in your database.",
            location: { file: configFile, line: i + 1 },
            remediation: "Remove the service_role key from client code. Only use it in server-side functions (Edge Functions, API routes). Use the anon key for client-side access with proper RLS policies.",
            cweId: "CWE-798",
            verified: true,
            tags: ["supabase", "service-role-exposed", "critical"],
          });
        }

        // Check for RLS disabled in config
        if (/rls\s*=\s*false/i.test(line) || /enable_rls\s*=\s*false/i.test(line)) {
          findings.push({
            id: uuid(),
            module: "database-checker",
            severity: "high",
            title: "RLS explicitly disabled in configuration",
            description: "Row Level Security is explicitly disabled in the Supabase configuration. This means all data is publicly accessible.",
            location: { file: configFile, line: i + 1 },
            remediation: "Enable RLS: set `rls = true` or remove the override.",
            tags: ["supabase", "rls-disabled"],
          });
        }
      }
    } catch {
      // File doesn't exist, skip
    }
  }

  // Check for SQL migrations with missing RLS
  try {
    const migrationsDir = join(targetPath, "supabase/migrations");
    const { readdir: rd } = await import("node:fs/promises");
    const migrations = await rd(migrationsDir);

    for (const migration of migrations) {
      if (!migration.endsWith(".sql")) continue;
      const content = await readFile(join(migrationsDir, migration), "utf-8");

      // Find CREATE TABLE without a corresponding ENABLE ROW LEVEL SECURITY
      const createTableMatches = content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)/gi);
      for (const match of createTableMatches) {
        const tableName = match[1];
        const hasRLS = new RegExp(
          `ALTER\\s+TABLE\\s+(?:public\\.)?${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
          "i"
        ).test(content);

        if (!hasRLS) {
          findings.push({
            id: uuid(),
            module: "database-checker",
            severity: "high",
            title: `Migration creates "${tableName}" without enabling RLS`,
            description: `The migration "${migration}" creates the "${tableName}" table but never enables Row Level Security. This table will be publicly accessible via the Supabase REST API.`,
            location: { file: `supabase/migrations/${migration}` },
            remediation: `Add to your migration:\n\nALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Restrict access" ON ${tableName} FOR ALL USING (auth.uid() = user_id);`,
            tags: ["supabase", "migration", "rls-missing"],
          });
        }
      }
    }
  } catch {
    // No migrations directory
  }

  return findings;
}

export async function runDatabaseChecker(config: ScanConfig): Promise<ModuleResult> {
  const start = Date.now();

  try {
    const findingsPromises: Promise<Finding[]>[] = [];

    // Always check local config files
    findingsPromises.push(checkLocalSupabaseConfig(config.target.path));

    // If Supabase config provided, do active probing
    if (config.supabase) {
      findingsPromises.push(checkSupabaseExposure(config.supabase));
    }

    const results = await Promise.all(findingsPromises);
    const allFindings = results.flat();

    let score = 100;
    for (const f of allFindings) {
      if (f.severity === "critical") score -= 25;
      else if (f.severity === "high") score -= 15;
      else if (f.severity === "medium") score -= 8;
      else if (f.severity === "low") score -= 3;
    }
    score = Math.max(0, score);

    const hasCritical = allFindings.some((f) => f.severity === "critical");
    const hasHigh = allFindings.some((f) => f.severity === "high");

    return {
      module: "database-checker",
      findings: allFindings,
      score,
      duration: Date.now() - start,
      status: hasCritical ? "failed" : hasHigh ? "warning" : allFindings.length > 0 ? "warning" : "passed",
    };
  } catch (error) {
    return {
      module: "database-checker",
      findings: [],
      score: 0,
      duration: Date.now() - start,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}
