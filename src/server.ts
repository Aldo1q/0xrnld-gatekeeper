// Long-lived server entry: `npm run build && npm start`.
import { loadConfig } from "./config";
import { createRuntime } from "./handler";
import { createHttpServer } from "./httpServer";
import { SeenStore } from "./store";

const config = loadConfig();
const store = new SeenStore(config.seenStorePath);
store.load();
const runtime = createRuntime(config, store);
const server = createHttpServer(runtime);

server.listen(config.port, () => {
  console.log(
    `0xrnld-gatekeeper listening on :${config.port} ` +
      `(kurier: ${config.kurierApiKey ? "configured" : "not configured — proofs returned without submission"}, ` +
      `seen: ${store.seenCount}, cached: ${store.cachedCount})`,
  );
});

const shutdown = async () => {
  await store.flush();
  server.close(() => process.exit(0));
};
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
