// Runtime configuration, read only from environment variables.
// No secret is ever hardcoded or committed.
import * as path from "node:path";

/** The gatekeeper verification-key hash registered for this event. */
export const DEFAULT_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const PREFLIGHT_TYPE = "agent-games.preflight.v1";
export const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";

export interface AgentConfig {
  hmacSecret: string | undefined;
  kurierApiKey: string | undefined;
  kurierApiUrl: string;
  vkHash: string;
  kurierPollBudgetMs: number;
  softDeadlineMs: number;
  seenStorePath: string;
  circuitsDir: string;
  port: number;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function defaultSeenStorePath(): string {
  // On Vercel the only writable directory is /tmp; it resets on cold start,
  // so the seen-set is best-effort there. A long-lived host keeps it on disk.
  const file = "0xrnld-gatekeeper-seen.json";
  if (process.env.VERCEL === "1") return path.join("/tmp", file);
  return path.join(process.cwd(), "data", file);
}

export function loadConfig(): AgentConfig {
  return {
    hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET || undefined,
    kurierApiKey: process.env.KURIER_API_KEY || undefined,
    kurierApiUrl: (process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1").replace(/\/$/, ""),
    vkHash: process.env.GATEKEEPER_VK_HASH || DEFAULT_VK_HASH,
    kurierPollBudgetMs: envInt("KURIER_POLL_BUDGET_MS", 15000),
    softDeadlineMs: envInt("TASK_SOFT_DEADLINE_MS", 50000),
    seenStorePath: process.env.SEEN_STORE_PATH || defaultSeenStorePath(),
    circuitsDir: process.env.CIRCUITS_DIR || path.join(process.cwd(), "circuits"),
    port: envInt("PORT", 8787),
  };
}
