// Vercel serverless entry for POST/GET /agent.
// bodyParser must stay off (see vercel.json) so the raw body reaches the
// HMAC check untouched. State lives in /tmp on Vercel and can reset on
// cold start — for maximum PROOF_REUSED reliability prefer a long-lived host.
import type { IncomingMessage, ServerResponse } from "node:http";
import { loadConfig } from "../src/config";
import { createRuntime, handleAgentPost } from "../src/handler";
import { SeenStore } from "../src/store";

type VercelRequest = IncomingMessage & {
  method?: string;
  query?: Record<string, string | string[]>;
};

type VercelResponse = ServerResponse & {
  status: (code: number) => VercelResponse;
  json: (body: unknown) => void;
  send: (body: string) => void;
};

const agentConfig = loadConfig();
const store = new SeenStore(agentConfig.seenStorePath);
store.load();
const runtime = createRuntime(agentConfig, store);

function readRawBody(req: VercelRequest): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "GET") {
    res.status(200).json({
      ok: true,
      service: "0xrnld-gatekeeper",
      protocolVersion: "v1",
      seen: store.seenCount,
      cached: store.cachedCount,
    });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "method not allowed" });
    return;
  }
  try {
    const raw = await readRawBody(req);
    const result = await handleAgentPost(runtime, raw, {
      "x-agent-games-signature": req.headers["x-agent-games-signature"] as string | undefined,
    });
    if (result.signature) res.setHeader("x-agent-games-signature", result.signature);
    res.status(result.status).setHeader("Content-Type", "application/json").send(result.body);
  } catch {
    res.status(500).json({ error: "internal error" });
  }
}

export const config = { api: { bodyParser: false } };
