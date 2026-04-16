// --- Severity & Finding Types ---

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ModuleName =
  | "secret-scanner"
  | "frontend-checker"
  | "database-checker"
  | "agent-checker";

export interface Location {
  file?: string;
  line?: number;
  column?: number;
  url?: string;
  table?: string;
}

export interface Finding {
  id: string;
  module: ModuleName;
  severity: Severity;
  title: string;
  description: string;
  location: Location;
  remediation: string;
  cweId?: string;
  evidence?: string;
  verified?: boolean;
  tags: string[];
}

// --- Scan Configuration ---

export interface ScanTarget {
  type: "repository" | "directory" | "url";
  path: string;
  branch?: string;
}

export interface SupabaseConfig {
  projectUrl: string;
  anonKey: string;
  serviceRoleKey?: string;
  managementApiToken?: string;
}

export interface AgentConfig {
  endpoints?: string[];
  modelProvider?: string;
  promptTemplates?: string[];
}

export interface ScanConfig {
  target: ScanTarget;
  modules: ModuleName[];
  supabase?: SupabaseConfig;
  agent?: AgentConfig;
  threshold?: number;
  outputFormat?: "json" | "html" | "pdf" | "text";
  verbose?: boolean;
}

// --- Scan Results ---

export interface ModuleResult {
  module: ModuleName;
  findings: Finding[];
  score: number;
  duration: number;
  status: "passed" | "failed" | "warning" | "error" | "skipped";
  error?: string;
}

export interface ScanReport {
  id: string;
  timestamp: string;
  target: ScanTarget;
  overallScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
  status: "passed" | "failed" | "warning";
  modules: ModuleResult[];
  findings: Finding[];
  summary: ScanSummary;
  metadata: ScanMetadata;
}

export interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  modulesRun: number;
  modulesPassed: number;
}

export interface ScanMetadata {
  scannerVersion: string;
  nodeVersion: string;
  platform: string;
  duration: number;
}

// --- Risk Scoring ---

export interface SeverityWeights {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ModuleWeights {
  "secret-scanner": number;
  "frontend-checker": number;
  "database-checker": number;
  "agent-checker": number;
}

// --- API Types ---

export interface ScanRequest {
  target: ScanTarget;
  modules?: ModuleName[];
  supabase?: SupabaseConfig;
  agent?: AgentConfig;
  threshold?: number;
}

export interface ScanResponse {
  scanId: string;
  status: "queued" | "running" | "completed" | "failed";
  report?: ScanReport;
  error?: string;
}

// --- Dashboard Types ---

export interface Project {
  id: string;
  name: string;
  platform: "lovable" | "bolt" | "v0" | "cursor" | "custom";
  lastScan?: ScanReport;
  scansCount: number;
  createdAt: string;
}
