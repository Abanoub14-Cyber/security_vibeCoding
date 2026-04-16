import { Router } from "express";
import { SCANNER_VERSION } from "@vibecode/shared";

export const healthRouter = Router();

healthRouter.get("/", (_req, res) => {
  res.json({
    status: "ok",
    version: SCANNER_VERSION,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});
