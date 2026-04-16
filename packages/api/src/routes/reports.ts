import { Router } from "express";

export const reportsRouter = Router();

// Placeholder for report listing and retrieval
// In production, this would query PostgreSQL
reportsRouter.get("/", (_req, res) => {
  res.json({ reports: [], total: 0 });
});
