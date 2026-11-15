// Framework-agnostic request pipeline for POST /agent.
// Order of operations:
//   1. HMAC-SHA256 over the RAW body (before any JSON parsing); mismatch -> 401
//   2. Preflight -> signed { ok: true, protocolVersion: "v1" }
//   3. Gatekeeper task -> idempotency cache -> policy -> proof -> Kurier
//      -> signed response. Fail closed at every step: any error or
//      uncertainty resolves to REJECT, never to an unproven APPROVE.
import type { AgentConfig } from "./config";
import { GATEKEEPER_TYPE, PREFLIGHT_TYPE } from "./config";
import { deriveSalt, signBody, verifySignature } from "./hmac";
import { hashStringToField } from "./field";
import { decide, parseInput, toCircuitSignals, type Decision, type ReasonCode } from "./policy";
import {
  circuitsPresent,
  loadVerificationKey,
  PUBLIC_SIGNAL_COUNT,
  prove,
  taskBindingHash,
} from "./prover";
import { submitToKurier } from "./kurier";
import type { SeenStore } from "./store";

export interface AgentResponse {
  status: number;
  body: string;
  signature: string | null;
}

export interface AgentRuntime {
  config: AgentConfig;
  store: SeenStore;
  verificationKey: unknown | null;
}

export function createRuntime(config: AgentConfig, store: SeenStore): AgentRuntime {
  let verificationKey: unknown | null = null;
  try {
    if (circuitsPresent(config.circuitsDir)) {
      verificationKey = loadVerificationKey(config.circuitsDir);
    }
  } catch {
    verificationKey = null;
  }
  return { config, store, verificationKey };
}

function signedJson(runtime: AgentRuntime, status: number, payload: Record<string, unknown>): AgentResponse {
  const body = JSON.stringify(payload);
  const signature = runtime.config.hmacSecret ? signBody(runtime.config.hmacSecret, Buffer.from(body, "utf8")) : null;
  return { status, body, signature };
}

function errorJson(runtime: AgentRuntime, status: number, message: string): AgentResponse {
  return signedJson(runtime, status, { error: message });
}

interface GatekeeperResponseBody {
  decision: Decision;
  reason_code: ReasonCode;
  proof?: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  public_signals?: string[];
  proof_tx: string | null;
}

export async function handleAgentPost(
  runtime: AgentRuntime,
  rawBody: Buffer,
  headers: Record<string, string | undefined>,
): Promise<AgentResponse> {
  const { config, store } = runtime;
  const startedAt = Date.now();

  if (!config.hmacSecret) {
    return errorJson(runtime, 500, "server misconfigured: AGENT_GAMES_HMAC_SECRET is not set");
  }
  const secret = config.hmacSecret;

  // 1. Authenticate before parsing anything.
  const signature = headers["x-agent-games-signature"];
  if (!verifySignature(secret, rawBody, signature)) {
    return errorJson(runtime, 401, "unauthorized: bad signature");
  }

  let envelope: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(rawBody.toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("envelope is not an object");
    }
    envelope = parsed as Record<string, unknown>;
  } catch {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: null,
    });
  }

  // 2. Preflight: liveness + protocol handshake.
  if (envelope.type === PREFLIGHT_TYPE) {
    return signedJson(runtime, 200, { ok: true, protocolVersion: "v1" });
  }
  if (envelope.type !== GATEKEEPER_TYPE) {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: null,
    });
  }

  const taskId = typeof envelope.task_id === "string" ? envelope.task_id : "";
  if (!taskId) {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: null,
    });
  }

  // 3. Idempotency: a retried task returns the identical response bytes.
  //    This check runs BEFORE the proof-reuse check so a redelivery is
  //    never misread as PROOF_REUSED.
  const cached = store.getCachedResponse(taskId);
  if (cached !== undefined) {
    return {
      status: 200,
      body: cached,
      signature: signBody(secret, Buffer.from(cached, "utf8")),
    };
  }

  // 4. Parse + validate the input. Malformed envelopes fail closed and are
  //    not cached (the platform may retry a corrected envelope).
  let input;
  try {
    input = parseInput(envelope.input);
  } catch {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: typeof envelope.input === "object" && envelope.input !== null
        ? String((envelope.input as Record<string, unknown>).proof_tx ?? "") || null
        : null,
    });
  }

  // 5. Deterministic policy.
  const { decision, reason } = decide(input, store.hasProofTx(input.proofTx));

  // PROOF_REUSED carries no proof — those tasks are excluded from proof scoring.
  if (reason === "PROOF_REUSED") {
    const body: GatekeeperResponseBody = {
      decision: "REJECT",
      reason_code: "PROOF_REUSED",
      proof_tx: input.proofTx,
    };
    const res = signedJson(runtime, 200, body as unknown as Record<string, unknown>);
    store.setCachedResponse(taskId, res.body);
    return res;
  }

  // 6. Prove. The circuit asserts decision == its own evaluation of the
  //    five checks, so a wrong decision fails witness generation here.
  if (!circuitsPresent(config.circuitsDir)) {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: input.proofTx,
    });
  }
  const taskIdField = hashStringToField(taskId);
  const salt = deriveSalt(secret, taskId);
  const signals = toCircuitSignals(input, taskIdField, salt, decision);
  let generated;
  try {
    generated = await prove(signals, config.circuitsDir);
  } catch {
    // Proof failure fails closed: never return an unproven APPROVE.
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: input.proofTx,
    });
  }

  // 7. Sanity-check the public signals locally: signal 0 is the
  //    Poseidon(salt, taskId) binding and signal 12 is the taskId hash
  //    (see the verified layout in src/prover.ts). Any mismatch means the
  //    proof does not describe this task — fail closed.
  try {
    const expectedFirst = (await taskBindingHash(salt, taskIdField)).toString(10);
    if (generated.publicSignals[0] !== expectedFirst) throw new Error("public signal 0 mismatch");
    if (generated.publicSignals.length !== PUBLIC_SIGNAL_COUNT) {
      throw new Error(`expected ${PUBLIC_SIGNAL_COUNT} public signals`);
    }
    if (generated.publicSignals[12] !== taskIdField.toString(10)) {
      throw new Error("public signal 12 (taskId) mismatch");
    }
  } catch {
    return signedJson(runtime, 200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: input.proofTx,
    });
  }

  // 8. Submit to Kurier (skipped gracefully when no API key is configured).
  let proofTx: string | null = input.proofTx;
  try {
    const outcome = await submitToKurier(
      {
        apiKey: config.kurierApiKey,
        apiUrl: config.kurierApiUrl,
        vkHash: config.vkHash,
        pollBudgetMs: config.kurierPollBudgetMs,
      },
      generated.proof,
      generated.publicSignals,
      startedAt,
      config.softDeadlineMs,
    );
    if (outcome.txHash) proofTx = outcome.txHash;
  } catch {
    /* submission is best-effort; the proof itself is the answer */
  }

  // 9. Record the proof_tx as seen and cache the response.
  store.markProofTx(input.proofTx, taskId);
  const responseBody: GatekeeperResponseBody = {
    decision,
    reason_code: reason,
    proof: generated.proof,
    public_signals: generated.publicSignals,
    proof_tx: proofTx,
  };
  const res = signedJson(runtime, 200, responseBody as unknown as Record<string, unknown>);
  store.setCachedResponse(taskId, res.body);
  return res;
}
