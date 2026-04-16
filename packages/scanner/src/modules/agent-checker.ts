import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { v4 as uuid } from "uuid";
import type { Finding, ModuleResult, ScanConfig } from "@vibecode/shared";

const execFileAsync = promisify(execFile);

const AGENT_FILE_PATTERNS = [
  /agent/i, /chain/i, /tool/i, /prompt/i, /llm/i,
  /langchain/i, /langgraph/i, /autogen/i, /crewai/i,
  /openai/i, /anthropic/i, /assistant/i,
];

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
]);

async function getAgentFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const extensions = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".mjs"]);

  async function walk(currentDir: string) {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (extensions.has(ext)) {
          // Check if filename or path suggests agent-related code
          const isAgentFile = AGENT_FILE_PATTERNS.some((p) => p.test(entry.name));
          if (isAgentFile) {
            files.push(fullPath);
          }
        }
      }
    }
  }

  await walk(dir);
  return files;
}

interface AgentPattern {
  pattern: RegExp;
  title: string;
  description: string;
  severity: Finding["severity"];
  remediation: string;
  tags: string[];
}

const AGENT_RISK_PATTERNS: AgentPattern[] = [
  {
    pattern: /eval\s*\(/g,
    title: "Dynamic code execution in agent context",
    description: "eval() is used in agent-related code. An attacker could inject malicious code through prompt injection.",
    severity: "critical",
    remediation: "Never use eval() with LLM outputs. Use a sandboxed execution environment or predefined function calls.",
    tags: ["code-injection", "eval"],
  },
  {
    pattern: /exec\s*\(|subprocess|child_process|spawn\s*\(/g,
    title: "Shell command execution in agent",
    description: "The agent can execute shell commands. Without proper sandboxing, prompt injection could lead to remote code execution.",
    severity: "critical",
    remediation: "Sandbox command execution. Use allowlists for permitted commands. Never pass LLM output directly to shell.",
    tags: ["rce", "command-injection"],
  },
  {
    pattern: /(?:fs|readFile|writeFile|unlink|rmdir).*(?:tool|agent|function_call)/gi,
    title: "File system access in agent tools",
    description: "The agent has tools that access the file system. Prompt injection could be used to read sensitive files or overwrite data.",
    severity: "high",
    remediation: "Restrict file access to specific directories. Use path validation and sanitization. Apply least-privilege principles.",
    tags: ["file-access", "agent-tool"],
  },
  {
    pattern: /(?:fetch|axios|request|http)\s*\(.*(?:tool|agent|user|input|prompt)/gi,
    title: "Unrestricted network access in agent",
    description: "The agent can make arbitrary HTTP requests. This could be exploited for SSRF attacks or data exfiltration via prompt injection.",
    severity: "high",
    remediation: "Restrict outbound requests to an allowlist of domains. Validate URLs before making requests.",
    tags: ["ssrf", "network-access"],
  },
  {
    pattern: /(?:sql|query|execute)\s*\(.*(?:tool|agent|input|user|prompt)/gi,
    title: "Database access via agent tool",
    description: "The agent has direct database query capabilities. Prompt injection could lead to SQL injection or data theft.",
    severity: "high",
    remediation: "Use parameterized queries. Restrict agent to read-only access on specific tables. Never pass LLM output directly to SQL.",
    tags: ["sql-injection", "database-access"],
  },
  {
    pattern: /system\s*(?:prompt|message|instruction)\s*[:=]\s*[`'"]/gi,
    title: "System prompt found in source code",
    description: "System prompts are hardcoded in source code. They may be extracted from the client bundle, revealing business logic or injection vectors.",
    severity: "medium",
    remediation: "Move system prompts to server-side configuration or environment variables. Never include them in client-shipped code.",
    tags: ["prompt-exposure", "system-prompt"],
  },
  {
    pattern: /(?:allowDangerousHtml|dangerouslySetInnerHTML|innerHTML)\s*(?:=|:)/gi,
    title: "Unsafe HTML rendering of LLM output",
    description: "LLM output may be rendered as raw HTML. An attacker could inject malicious HTML/JS through prompt injection (indirect XSS).",
    severity: "high",
    remediation: "Sanitize all LLM output before rendering. Use a library like DOMPurify. Never use dangerouslySetInnerHTML with AI output.",
    tags: ["xss", "html-injection"],
  },
  {
    pattern: /(?:tools|functions)\s*[:=]\s*\[/gi,
    title: "Agent tool definitions detected",
    description: "Agent tool/function definitions found. Review to ensure proper input validation and least-privilege access.",
    severity: "info",
    remediation: "Ensure each tool validates its inputs, has appropriate timeouts, and follows the principle of least privilege.",
    tags: ["agent-tools", "review"],
  },
  {
    pattern: /(?:auto[_-]?approve|auto[_-]?execute|skip[_-]?confirm)/gi,
    title: "Auto-approval of agent actions",
    description: "Agent actions are configured to auto-approve without human confirmation. Critical actions should require human-in-the-loop.",
    severity: "high",
    remediation: "Require human confirmation for destructive or sensitive operations (deleting data, sending emails, making payments).",
    tags: ["auto-approve", "human-in-the-loop"],
  },
  {
    pattern: /(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|api[_-]?key)\s*[:=]\s*(?:process\.env|import\.meta)/gi,
    title: "AI API key configuration in agent code",
    description: "API key for an AI provider is configured in agent code. Ensure it's not exposed to the client.",
    severity: "info",
    remediation: "Verify the API key is only used server-side and never included in client bundles.",
    tags: ["api-key", "configuration"],
  },
  {
    pattern: /(?:user[_-]?input|user[_-]?message|prompt)\s*\+\s*(?:system|instruction)/gi,
    title: "User input concatenated with system prompt",
    description: "User input is directly concatenated with system prompts. This is the primary vector for prompt injection attacks.",
    severity: "high",
    remediation: "Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.",
    tags: ["prompt-injection", "concatenation"],
  },
];

async function scanAgentFiles(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await getAgentFiles(targetPath);

  // Also scan all files for agent patterns (not just agent-named files)
  const allFiles = await getAllSourceFiles(targetPath);
  const allFilesToScan = [...new Set([...files, ...allFiles])];

  for (const filePath of allFilesToScan) {
    let content: string;
    try {
      const fileStat = await stat(filePath);
      if (fileStat.size > 500_000) continue;
      content = await readFile(filePath, "utf-8");
    } catch {
      continue;
    }

    const relPath = relative(targetPath, filePath);
    const lines = content.split("\n");

    for (const agentPattern of AGENT_RISK_PATTERNS) {
      const { pattern, title, description, severity, remediation, tags } = agentPattern;

      for (let i = 0; i < lines.length; i++) {
        // Reset regex
        pattern.lastIndex = 0;
        if (pattern.test(lines[i])) {
          findings.push({
            id: uuid(),
            module: "agent-checker",
            severity,
            title,
            description,
            location: { file: relPath, line: i + 1 },
            remediation,
            evidence: lines[i].trim().substring(0, 100),
            tags: ["agent-security", ...tags],
          });
          break; // One finding per pattern per file
        }
      }
    }
  }

  return findings;
}

async function getAllSourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const extensions = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".mjs"]);

  async function walk(currentDir: string) {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (extensions.has(ext)) files.push(fullPath);
      }
    }
  }

  await walk(dir);
  return files;
}

async function checkMCPConfig(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const mcpConfigFiles = [
    "mcp.json",
    ".mcp/config.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
  ];

  for (const configFile of mcpConfigFiles) {
    try {
      const content = await readFile(join(targetPath, configFile), "utf-8");
      const config = JSON.parse(content);

      // Check for overly permissive MCP server configurations
      const servers = config.mcpServers || config.servers || {};
      for (const [serverName, serverConfig] of Object.entries(servers)) {
        const sc = serverConfig as any;

        // Check for filesystem access
        if (sc.command?.includes("filesystem") || sc.args?.some?.((a: string) => a.includes("/"))) {
          findings.push({
            id: uuid(),
            module: "agent-checker",
            severity: "medium",
            title: `MCP server "${serverName}" has filesystem access`,
            description: `The MCP server "${serverName}" is configured with filesystem access. Ensure directories are properly scoped.`,
            location: { file: configFile },
            remediation: "Restrict filesystem MCP servers to specific, minimal directories. Never expose system directories.",
            tags: ["mcp", "filesystem-access"],
          });
        }

        // Check for environment variables with secrets
        if (sc.env) {
          for (const [key, value] of Object.entries(sc.env)) {
            if (/key|secret|token|password/i.test(key) && typeof value === "string" && value.length > 10) {
              findings.push({
                id: uuid(),
                module: "agent-checker",
                severity: "high",
                title: `MCP server "${serverName}" has hardcoded credential: ${key}`,
                description: `The MCP configuration contains a hardcoded credential in the "${key}" environment variable.`,
                location: { file: configFile },
                remediation: "Use environment variable references instead of hardcoded values.",
                tags: ["mcp", "hardcoded-credential"],
              });
            }
          }
        }
      }
    } catch {
      // File doesn't exist or invalid JSON
    }
  }

  return findings;
}

async function runGarak(targetPath: string): Promise<Finding[]> {
  try {
    // Check if garak is installed
    await execFileAsync("garak", ["--version"], { timeout: 5000 });

    // Garak requires a running model endpoint — just check if config exists
    const findings: Finding[] = [];
    findings.push({
      id: uuid(),
      module: "agent-checker",
      severity: "info",
      title: "Garak available for LLM testing",
      description: "NVIDIA Garak is installed and can be used for comprehensive prompt injection testing. Run `garak --model_type rest --probes all` against your agent endpoints.",
      location: { file: "N/A" },
      remediation: "Run Garak against your production agent endpoints before deployment.",
      tags: ["garak", "available"],
    });
    return findings;
  } catch {
    return [];
  }
}

async function runPromptfoo(targetPath: string): Promise<Finding[]> {
  try {
    await execFileAsync("promptfoo", ["--version"], { timeout: 5000 });
    return [{
      id: uuid(),
      module: "agent-checker",
      severity: "info",
      title: "Promptfoo available for red-teaming",
      description: "Promptfoo is installed and can run automated red-team tests against your AI features.",
      location: { file: "N/A" },
      remediation: "Create a promptfooconfig.yaml and run `promptfoo redteam` to test for vulnerabilities.",
      tags: ["promptfoo", "available"],
    }];
  } catch {
    return [];
  }
}

export async function runAgentChecker(config: ScanConfig): Promise<ModuleResult> {
  const start = Date.now();

  try {
    const [agentFindings, mcpFindings, garakFindings, promptfooFindings] = await Promise.all([
      scanAgentFiles(config.target.path),
      checkMCPConfig(config.target.path),
      runGarak(config.target.path),
      runPromptfoo(config.target.path),
    ]);

    const allFindings = [
      ...agentFindings,
      ...mcpFindings,
      ...garakFindings,
      ...promptfooFindings,
    ];

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
      module: "agent-checker",
      findings: allFindings,
      score,
      duration: Date.now() - start,
      status: hasCritical ? "failed" : hasHigh ? "warning" : allFindings.length > 0 ? "warning" : "passed",
    };
  } catch (error) {
    return {
      module: "agent-checker",
      findings: [],
      score: 0,
      duration: Date.now() - start,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}
