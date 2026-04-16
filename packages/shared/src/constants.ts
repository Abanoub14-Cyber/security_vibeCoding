import type { SeverityWeights, ModuleWeights } from "./types.js";

export const SCANNER_VERSION = "1.0.0";

export const SEVERITY_WEIGHTS: SeverityWeights = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export const MODULE_WEIGHTS: ModuleWeights = {
  "secret-scanner": 0.30,
  "frontend-checker": 0.25,
  "database-checker": 0.30,
  "agent-checker": 0.15,
};

export const GRADE_THRESHOLDS = {
  A: 90,
  B: 75,
  C: 60,
  D: 40,
  F: 0,
} as const;

// Common secret patterns for vibe-coded apps
export const SECRET_PATTERNS = {
  // Supabase
  SUPABASE_SERVICE_ROLE: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/,
  SUPABASE_ANON_KEY_IN_CODE: /(?:service_role|secret|private).*(?:eyJhbGci)[A-Za-z0-9_.-]+/i,

  // OpenAI
  OPENAI_API_KEY: /sk-[A-Za-z0-9]{20,}/,
  OPENAI_PROJECT_KEY: /sk-proj-[A-Za-z0-9_-]{40,}/,

  // Anthropic
  ANTHROPIC_API_KEY: /sk-ant-[A-Za-z0-9_-]{40,}/,

  // Stripe
  STRIPE_SECRET_KEY: /sk_live_[A-Za-z0-9]{24,}/,
  STRIPE_RESTRICTED_KEY: /rk_live_[A-Za-z0-9]{24,}/,

  // Google
  GOOGLE_API_KEY: /AIza[A-Za-z0-9_-]{35}/,

  // Firebase
  FIREBASE_PRIVATE_KEY: /-----BEGIN (?:RSA )?PRIVATE KEY-----/,

  // AWS
  AWS_ACCESS_KEY: /AKIA[A-Z0-9]{16}/,
  AWS_SECRET_KEY: /(?:aws_secret|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}/i,

  // Generic
  GENERIC_PRIVATE_KEY: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
  GENERIC_API_KEY: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]/i,
  GENERIC_SECRET: /(?:secret|password|token|credential)\s*[:=]\s*['"][A-Za-z0-9_/+=!@#$%^&*()-]{8,}['"]/i,
} as const;

// Vibe-coding specific: public env prefix patterns that shouldn't contain secrets
export const PUBLIC_ENV_PATTERNS = [
  /VITE_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=/i,
  /NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=/i,
  /REACT_APP_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=/i,
  /NUXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=/i,
  /EXPO_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=/i,
];

// Common Supabase tables to probe
export const COMMON_TABLES = [
  "users",
  "profiles",
  "accounts",
  "payments",
  "orders",
  "transactions",
  "api_keys",
  "tokens",
  "sessions",
  "messages",
  "documents",
  "files",
  "settings",
  "configs",
  "secrets",
  "customers",
  "invoices",
  "subscriptions",
];

// Dangerous client-side API patterns
export const DANGEROUS_CLIENT_PATTERNS = [
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/api\.openai\.com/gi, name: "OpenAI API called from client" },
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/api\.anthropic\.com/gi, name: "Anthropic API called from client" },
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/api\.stripe\.com/gi, name: "Stripe API called from client" },
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/api\.twilio\.com/gi, name: "Twilio API called from client" },
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/api\.sendgrid\.com/gi, name: "SendGrid API called from client" },
  { pattern: /new\s+OpenAI\s*\(/gi, name: "OpenAI SDK initialized client-side" },
  { pattern: /new\s+Anthropic\s*\(/gi, name: "Anthropic SDK initialized client-side" },
  { pattern: /new\s+Stripe\s*\(/gi, name: "Stripe SDK initialized client-side (secret key)" },
];

// Firebase insecure rules patterns
export const FIREBASE_INSECURE_PATTERNS = [
  { pattern: /allow\s+read\s*,\s*write\s*:\s*if\s+true/gi, name: "Firebase: fully open read/write" },
  { pattern: /allow\s+read\s*:\s*if\s+true/gi, name: "Firebase: open read access" },
  { pattern: /allow\s+write\s*:\s*if\s+true/gi, name: "Firebase: open write access" },
  { pattern: /allow\s+delete\s*:\s*if\s+true/gi, name: "Firebase: open delete access" },
];
