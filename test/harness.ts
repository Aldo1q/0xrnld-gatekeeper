// End-to-end harness: boots the real server on an ephemeral port and
// replays spec-shaped envelopes. Exits non-zero if any check fails.
//
//   npm test
//
// Coverage: HMAC roundtrip (hex + base64), tamper / wrong-secret / missing
// -> 401; preflight shape + signed response; valid task -> APPROVE with a
// proof that verifies against the extracted verification key; all six
// traps -> correct REJECT + reason_code with verified proofs (except
// PROOF_REUSED, which carries no proof); boundary inclusivity;
// idempotent redelivery; witness generation fails for a wrong decision.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHmac } from "node:crypto";

process.env.AGENT_GAMES_HMAC_SECRET = "harness-test-secret-do-not-use-in-prod";
delete process.env.KURIER_API_KEY;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "gk-harness-"));
process.env.SEEN_STORE_PATH = path.join(TMP, "seen.json");
process.env.CIRCUITS_DIR = path.join(process.cwd(), "circuits");
process.env.KURIER_POLL_BUDGET_MS = "1000";
process.env.TASK_SOFT_DEADLINE_MS = "50000";

import { loadConfig } from "../src/config";
import { deriveSalt, signBody, verifySignature } from "../src/hmac";
import { hashStringToField } from "../src/field";
import { parseInput, toCircuitSignals } from "../src/policy";
import { createRuntime } from "../src/handler";
import { createHttpServer } from "../src/httpServer";
import { SeenStore } from "../src/store";
import { loadVerificationKey, prove, taskBindingHash, verifyProof } from "../src/prover";
import * as snarkjs from "snarkjs";

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET as string;
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ALICE = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, ok: boolean, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

function tx(n: number): string {
  return "0x" + n.toString(16).padStart(64, "a");
}

function envelope(taskId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ALICE,
      condition_recipient: ALICE,
      amount: "500",
      max_transfer: "1000",
      proof_tx: tx(1),
      ...overrides,
    },
  };
}

async function post(
  base: string,
  body: string,
  opts: { secret?: string; encoding?: "hex" | "base64" | "sha256="; rawHeader?: string; signOver?: string } = {},
): Promise<{ status: number; text: string; sig: string | null }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.rawHeader !== undefined) {
    if (opts.rawHeader) headers["x-agent-games-signature"] = opts.rawHeader;
  } else {
    // signOver lets the tamper test sign the original body but send a
    // modified one; by default the signature covers the sent body.
    const mac = createHmac("sha256", Buffer.from(opts.secret ?? SECRET, "utf8"))
      .update(Buffer.from(opts.signOver ?? body, "utf8"))
      .digest();
    headers["x-agent-games-signature"] =
      opts.encoding === "base64"
        ? mac.toString("base64")
        : opts.encoding === "sha256="
          ? "sha256=" + mac.toString("hex")
          : mac.toString("hex");
  }
  const res = await fetch(base + "/agent", { method: "POST", headers, body });
  return { status: res.status, text: await res.text(), sig: res.headers.get("x-agent-games-signature") };
}

function responseSignatureValid(text: string, sig: string | null): boolean {
  return sig !== null && verifySignature(SECRET, Buffer.from(text, "utf8"), sig);
}

async function main(): Promise<void> {
  const config = loadConfig();
  const store = new SeenStore(config.seenStorePath);
  store.load();
  const runtime = createRuntime(config, store);
  const server = createHttpServer(runtime);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("no listen address");
  const base = `http://127.0.0.1:${address.port}`;
  const timings: number[] = [];

  try {
    // --- health check -------------------------------------------------------
    console.log("health:");
    const health = await fetch(base + "/agent");
    check("GET /agent returns 200 ok", health.status === 200 && ((await health.json()) as Record<string, unknown>).ok === true);

    // --- HMAC + preflight ---------------------------------------------------
    console.log("hmac + preflight:");
    const preBody = JSON.stringify({ type: "agent-games.preflight.v1", task_id: "pf_1" });
    const t0 = Date.now();
    const pf = await post(base, preBody);
    timings.push(Date.now() - t0);
    check("preflight status 200", pf.status === 200);
    const pfJson = JSON.parse(pf.text) as Record<string, unknown>;
    check("preflight body {ok:true, protocolVersion:v1}", pfJson.ok === true && pfJson.protocolVersion === "v1");
    check("preflight response signature valid", responseSignatureValid(pf.text, pf.sig));

    const pfB64 = await post(base, preBody, { encoding: "base64" });
    check("preflight accepts base64 signature", pfB64.status === 200);
    const pfPrefixed = await post(base, preBody, { encoding: "sha256=" });
    check("preflight accepts sha256= prefix", pfPrefixed.status === 200);
    const pfWrong = await post(base, preBody, { secret: "wrong-secret" });
    check("wrong secret -> 401", pfWrong.status === 401);
    const pfMissing = await post(base, preBody, { rawHeader: "" });
    check("missing signature -> 401", pfMissing.status === 401);
    const pfTampered = await post(base, preBody.replace("preflight", "preflighx"), { signOver: preBody });
    check("tampered body -> 401", pfTampered.status === 401);

    // --- verification key ---------------------------------------------------
    console.log("verification key:");
    const vkPath = path.join(process.cwd(), "circuits", "verification_key.json");
    if (!fs.existsSync(vkPath)) {
      const vk = await snarkjs.zKey.exportVerificationKey(
        path.join(process.cwd(), "circuits", "gatekeeper_final.zkey"),
      );
      fs.writeFileSync(vkPath, JSON.stringify(vk, null, 2));
      console.log("  (exported verification_key.json from zkey)");
    }
    const vk = loadVerificationKey(config.circuitsDir);
    check("verification key loads", !!vk);

    // --- valid task ---------------------------------------------------------
    console.log("valid task:");
    const validTaskId = "gk_valid_001";
    const validBody = JSON.stringify(envelope(validTaskId));
    const t1 = Date.now();
    const valid = await post(base, validBody);
    timings.push(Date.now() - t1);
    check("valid task status 200", valid.status === 200, `got ${valid.status}: ${valid.text.slice(0, 200)}`);
    check("valid response signature valid", responseSignatureValid(valid.text, valid.sig));
    const validJson = JSON.parse(valid.text) as Record<string, unknown>;
    check("valid task APPROVE", validJson.decision === "APPROVE", String(validJson.decision));
    check("valid task VALID_CONDITION", validJson.reason_code === "VALID_CONDITION", String(validJson.reason_code));
    const signals = validJson.public_signals as string[] | undefined;
    check("13 public signals", Array.isArray(signals) && signals.length === 13, `got ${signals?.length}`);
    const proof = validJson.proof as { pi_a: string[]; pi_b: string[][]; pi_c: string[] } | undefined;
    // snarkjs groth16 proofs carry homogeneous coordinates: pi_a/pi_c are
    // 3 elements [x, y, 1] and pi_b is 3 rows of 2.
    check("proof present with groth16/bn128", !!proof && proof.pi_a?.length === 3 && proof.pi_c?.length === 3 && proof.pi_b?.length === 3);
    if (proof && signals) {
      const ok = await verifyProof(vk, { ...proof, protocol: "groth16", curve: "bn128" }, signals);
      check("snarkjs groth16 verify OK", ok === true);
      const taskIdField = hashStringToField(validTaskId);
      const salt = deriveSalt(SECRET, validTaskId);
      const expectedFirst = (await taskBindingHash(salt, taskIdField)).toString(10);
      check("public signal 0 == Poseidon(salt, taskId)", signals[0] === expectedFirst);
      check("public signal 12 == taskId hash", signals[12] === taskIdField.toString(10));
      // Verified circuit layout: [Poseidon(salt,taskId), registeredVkHash,
      // proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
      // recipient, conditionRecipient, amount, maxTransfer, decision, taskId]
      const vkField = "4836144126773920907502496244340012141465762957689769435993496290439317388578";
      const aliceField = "97433442488726861213578988847752201310395502865";
      check(
        "public signals match the verified circuit layout",
        signals[1] === vkField &&
          signals[2] === vkField &&
          signals[3] === "1000" &&
          signals[4] === "1460" &&
          signals[5] === "8430000" &&
          signals[6] === "8420000" &&
          signals[7] === aliceField &&
          signals[8] === aliceField &&
          signals[9] === "500" &&
          signals[10] === "1000" &&
          signals[11] === "1",
        JSON.stringify(signals),
      );
    }
    check("proof_tx echoes input when Kurier is unset", validJson.proof_tx === tx(1), String(validJson.proof_tx));

    // --- idempotent redelivery ----------------------------------------------
    console.log("idempotency:");
    const again = await post(base, validBody);
    check("redelivery returns identical body", again.text === valid.text);
    check("redelivery keeps one seen entry", store.seenCount === 1, `seen=${store.seenCount}`);

    // --- six traps ------------------------------------------------------------
    console.log("traps:");
    const traps: Array<{ name: string; overrides: Record<string, unknown>; reason: string; txN: number }> = [
      { name: "VK_SUBSTITUTION", overrides: { proof_vk: "0x" + "9".repeat(64) }, reason: "VK_SUBSTITUTION", txN: 2 },
      { name: "PROOF_REUSED", overrides: { proof_tx: tx(1) }, reason: "PROOF_REUSED", txN: 1 },
      { name: "THRESHOLD_MISMATCH", overrides: { public_balance: "999" }, reason: "THRESHOLD_MISMATCH", txN: 3 },
      { name: "EXPIRED_CONDITION", overrides: { current_block: 8430000 }, reason: "EXPIRED_CONDITION", txN: 4 },
      { name: "RECIPIENT_MISMATCH", overrides: { recipient: BOB }, reason: "RECIPIENT_MISMATCH", txN: 5 },
      { name: "AMOUNT_OVERFLOW", overrides: { amount: "1001" }, reason: "AMOUNT_OVERFLOW", txN: 6 },
    ];
    for (const trap of traps) {
      const taskId = `gk_trap_${trap.name.toLowerCase()}`;
      const t = Date.now();
      const res = await post(base, JSON.stringify(envelope(taskId, { proof_tx: tx(trap.txN), ...trap.overrides })));
      timings.push(Date.now() - t);
      const j = JSON.parse(res.text) as Record<string, unknown>;
      check(`${trap.name}: status 200`, res.status === 200, `got ${res.status}`);
      check(`${trap.name}: REJECT`, j.decision === "REJECT", String(j.decision));
      check(`${trap.name}: reason ${trap.reason}`, j.reason_code === trap.reason, String(j.reason_code));
      check(`${trap.name}: response signature valid`, responseSignatureValid(res.text, res.sig));
      if (trap.reason === "PROOF_REUSED") {
        check("PROOF_REUSED: no proof field", j.proof === undefined && j.public_signals === undefined);
      } else {
        const p = j.proof as { pi_a: string[]; pi_b: string[][]; pi_c: string[] } | undefined;
        const s = j.public_signals as string[] | undefined;
        check(`${trap.name}: proof present`, !!p && Array.isArray(s) && s.length === 13);
        if (p && s) {
          const ok = await verifyProof(vk, { ...p, protocol: "groth16", curve: "bn128" }, s);
          check(`${trap.name}: proof verifies`, ok === true);
        }
      }
    }

    // --- boundary inclusivity --------------------------------------------------
    console.log("boundaries:");
    const b1 = await post(base, JSON.stringify(envelope("gk_edge_balance", { proof_tx: tx(11), public_balance: "1000" })));
    const b1j = JSON.parse(b1.text) as Record<string, unknown>;
    check("balance == minimum approves", b1j.decision === "APPROVE", String(b1j.decision));
    const b2 = await post(base, JSON.stringify(envelope("gk_edge_amount", { proof_tx: tx(12), amount: "1000" })));
    const b2j = JSON.parse(b2.text) as Record<string, unknown>;
    check("amount == max_transfer approves", b2j.decision === "APPROVE", String(b2j.decision));
    const b3 = await post(base, JSON.stringify(envelope("gk_edge_block", { proof_tx: tx(13), current_block: 8429999 })));
    const b3j = JSON.parse(b3.text) as Record<string, unknown>;
    check("current_block == expiry-1 approves", b3j.decision === "APPROVE", String(b3j.decision));

    // --- malformed envelope ------------------------------------------------------
    console.log("malformed:");
    const bad = await post(base, JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", task_id: "gk_bad_1", input: { registered_vk: "not-hex" } }));
    const badJ = JSON.parse(bad.text) as Record<string, unknown>;
    check("malformed input -> REJECT INVALID_TASK", bad.status === 200 && badJ.decision === "REJECT" && badJ.reason_code === "INVALID_TASK");
    const badJson = await post(base, "{not json");
    check("unparseable body -> REJECT INVALID_TASK", badJson.status === 200 && (JSON.parse(badJson.text) as Record<string, unknown>).reason_code === "INVALID_TASK");

    // --- circuit is the referee: wrong decision must fail witness generation --
    console.log("circuit referee:");
    const trapped = parseInput(envelope("gk_referee_1", { proof_tx: tx(21), public_balance: "999" }).input);
    const trappedSignals = toCircuitSignals(trapped, hashStringToField("gk_referee_1"), deriveSalt(SECRET, "gk_referee_1"), "APPROVE");
    let wrongApproveFailed = false;
    try {
      await prove(trappedSignals, config.circuitsDir);
    } catch {
      wrongApproveFailed = true;
    }
    check("decision=1 on a trapped statement fails witness generation", wrongApproveFailed);
    const validInput = parseInput(envelope("gk_referee_2", { proof_tx: tx(22) }).input);
    const validSignals = toCircuitSignals(validInput, hashStringToField("gk_referee_2"), deriveSalt(SECRET, "gk_referee_2"), "REJECT");
    let wrongRejectFailed = false;
    try {
      await prove(validSignals, config.circuitsDir);
    } catch {
      wrongRejectFailed = true;
    }
    check("decision=0 on a valid statement fails witness generation", wrongRejectFailed);

    // --- durability ---------------------------------------------------------
    console.log("durability:");
    await store.flush();
    check("seen store file written", fs.existsSync(config.seenStorePath));
    const reloaded = new SeenStore(config.seenStorePath);
    reloaded.load();
    check("seen-set survives reload", reloaded.hasProofTx(tx(1)) && reloaded.getCachedResponse(validTaskId) === valid.text);

    console.log(`\nresponse times (ms): ${timings.join(", ")} — max ${Math.max(...timings)}`);
  } finally {
    await store.flush();
    server.close();
  }

  console.log(`\n${passed} passed, ${failed} failed${failures.length ? " — " + failures.join("; ") : ""}`);
  // snarkjs/circom keep event-loop handles open; exit explicitly.
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("harness crashed:", e);
  process.exit(1);
});
