// Download the official gatekeeper circuit artifacts into circuits/.
// Used by the Vercel build (see vercel.json buildCommand) and by local
// setup: `npm run fetch-circuits`. Skips files that already exist.
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");

const BASE = "https://agentgames.zkverify.io/circuits";
const FILES = ["gatekeeper.wasm", "gatekeeper_final.zkey"];

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "0xrnld-gatekeeper" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, dest).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
      }
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on("finish", () => out.close(resolve));
      out.on("error", reject);
    });
    req.on("error", reject);
  });
}

(async () => {
  const dir = path.join(__dirname, "..", "circuits");
  fs.mkdirSync(dir, { recursive: true });
  for (const file of FILES) {
    const dest = path.join(dir, file);
    if (fs.existsSync(dest) && fs.statSync(dest).size > 0) {
      console.log(`exists: ${file} (${fs.statSync(dest).size} bytes)`);
      continue;
    }
    console.log(`downloading ${file} ...`);
    await download(`${BASE}/${file}`, dest);
    console.log(`saved: ${file} (${fs.statSync(dest).size} bytes)`);
  }
})().catch((e) => {
  console.error("fetch-circuits failed:", e.message);
  process.exit(1);
});
