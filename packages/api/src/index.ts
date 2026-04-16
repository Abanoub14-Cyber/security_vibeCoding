import express from "express";
import cors from "cors";
import { scanRouter } from "./routes/scan.js";
import { reportsRouter } from "./routes/reports.js";
import { healthRouter } from "./routes/health.js";

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Routes
app.use("/api/health", healthRouter);
app.use("/api/scan", scanRouter);
app.use("/api/reports", reportsRouter);

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`VibeCode Security Gate API running on port ${PORT}`);
});

export default app;
