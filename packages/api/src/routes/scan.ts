import { Router } from "express";
import { scan } from "@vibecode/scanner";
import type { ScanConfig, ScanRequest, ModuleName } from "@vibecode/shared";

export const scanRouter = Router();

// In-memory store for scan results (replace with PostgreSQL in production)
const scanResults = new Map<string, any>();

scanRouter.post("/", async (req, res) => {
  try {
    const body: ScanRequest = req.body;

    if (!body.target?.path) {
      res.status(400).json({ error: "target.path is required" });
      return;
    }

    const config: ScanConfig = {
      target: body.target,
      modules: body.modules || ["secret-scanner", "frontend-checker", "database-checker", "agent-checker"] as ModuleName[],
      supabase: body.supabase,
      agent: body.agent,
      threshold: body.threshold || 70,
    };

    const report = await scan(config);
    scanResults.set(report.id, report);

    res.json({
      scanId: report.id,
      status: "completed",
      report,
    });
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Scan failed",
    });
  }
});

scanRouter.get("/:id", (req, res) => {
  const report = scanResults.get(req.params.id);
  if (!report) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  res.json({ scanId: report.id, status: "completed", report });
});
