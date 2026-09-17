import express, { type NextFunction, type Request, type Response } from "express";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkConnectivity, parseTarget } from "./connectivity.js";

const port = Number(process.env.PORT ?? 8080);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port");

const app = express();
app.disable("x-powered-by");
app.use((_request, response, next) => {
  response.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  next();
});
app.use(express.json({ limit: "4kb" }));

const requestWindows = new Map<string, { count: number; startedAt: number }>();
app.use("/api/check", (request, response, next) => {
  const key = request.ip ?? "unknown";
  const now = Date.now();
  const record = requestWindows.get(key);
  if (!record || now - record.startedAt > 60_000) requestWindows.set(key, { count: 1, startedAt: now });
  else {
    record.count += 1;
    if (record.count > 30) {
      response.status(429).json({ error: "Too many checks. Try again in a minute." });
      return;
    }
  }
  next();
});

app.get("/healthz", (_request, response) => response.status(200).json({ status: "ok" }));
app.get("/readyz", (_request, response) => response.status(200).json({ status: "ready" }));

app.post("/api/check", async (request, response, next) => {
  const started = Date.now();
  try {
    if (typeof request.body?.target !== "string") {
      response.status(400).json({ error: "A target string is required." });
      return;
    }
    const parsed = parseTarget(request.body.target);
    const result = await checkConnectivity(parsed);
    console.log(JSON.stringify({ level: "info", event: "connectivity_check_completed", requestId: result.id, verdict: result.verdict, durationMs: Date.now() - started }));
    response.json(result);
  } catch (error) {
    if (error instanceof Error && /^(Enter|Target|Targets|Credentials|Supported|A tcp|Port)/.test(error.message)) {
      response.status(400).json({ error: error.message });
      return;
    }
    next(error);
  }
});

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
app.use(express.static(publicDir, { extensions: ["html"], maxAge: "1h" }));

app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  console.error(JSON.stringify({ level: "error", event: "request_failed", error: error instanceof Error ? error.name : "UnknownError" }));
  response.status(500).json({ error: "The connectivity check could not be completed." });
});

const server = http.createServer(app);
server.on("error", (error) => {
  console.error(JSON.stringify({ level: "error", event: "server_failed", error: error.name }));
  process.exitCode = 1;
});
server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ level: "info", event: "server_started", port }));
});

let shuttingDown = false;
function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ level: "info", event: "shutdown_started", signal }));
  server.close((error) => {
    if (error) {
      console.error(JSON.stringify({ level: "error", event: "shutdown_failed", error: error.name }));
      process.exitCode = 1;
    }
    process.exit();
  });
  setTimeout(() => {
    console.error(JSON.stringify({ level: "error", event: "shutdown_forced" }));
    process.exit(1);
  }, 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
