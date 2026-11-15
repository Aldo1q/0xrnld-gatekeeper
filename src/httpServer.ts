// Plain Node HTTP server: GET /agent is the health check, POST /agent is
// the signed task endpoint. No framework, no body parsing before HMAC —
// the raw body is collected first and handed to the pipeline untouched.
import * as http from "node:http";
import type { AgentRuntime } from "./handler";
import { handleAgentPost } from "./handler";

export function createHttpServer(runtime: AgentRuntime): http.Server {
  return http.createServer((req, res) => {
    const url = req.url ?? "/";
    const path = url.split("?")[0];
    if (path === "/agent" && req.method === "GET") {
      const body = JSON.stringify({
        ok: true,
        service: "0xrnld-gatekeeper",
        protocolVersion: "v1",
        seen: runtime.store.seenCount,
        cached: runtime.store.cachedCount,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
      return;
    }
    if (path === "/" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, service: "0xrnld-gatekeeper" }));
      return;
    }
    if (path === "/agent" && req.method === "POST") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("error", () => {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "bad request" }));
      });
      req.on("end", () => {
        void (async () => {
          try {
            const result = await handleAgentPost(runtime, Buffer.concat(chunks), {
              "x-agent-games-signature": req.headers["x-agent-games-signature"] as string | undefined,
            });
            const headers: Record<string, string> = { "Content-Type": "application/json" };
            if (result.signature) headers["x-agent-games-signature"] = result.signature;
            res.writeHead(result.status, headers);
            res.end(result.body);
          } catch {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "internal error" }));
          }
        })();
      });
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
}
