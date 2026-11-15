// Deterministic APPROVE/REJECT policy for a gatekeeper task.
// APPROVE only if EVERY check holds; boundaries are inclusive:
//   balance >= minimum, current_block < expiry_block, amount <= max_transfer.
// The circuit asserts decision == (all five field checks), so the policy
// here must mirror the circuit exactly — a wrong decision is unprovable.
import { decToField, hexToField, isHexString, normaliseHex } from "./field";

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "PROOF_REUSED"
  | "THRESHOLD_MISMATCH"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "INVALID_TASK"; // local fallback for envelope-level failures only

export interface GatekeeperInput {
  registeredVk: string;
  proofVk: string;
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: string;
  conditionRecipient: string;
  amount: bigint;
  maxTransfer: bigint;
  proofTx: string;
}

export interface DecisionResult {
  decision: Decision;
  reason: ReasonCode;
}

/** Check order is fixed so a task failing several checks always yields the same reason. */
export function decide(input: GatekeeperInput, proofTxSeen: boolean): DecisionResult {
  if (normaliseHex(input.proofVk) !== normaliseHex(input.registeredVk)) {
    return { decision: "REJECT", reason: "VK_SUBSTITUTION" };
  }
  if (proofTxSeen) {
    return { decision: "REJECT", reason: "PROOF_REUSED" };
  }
  if (input.publicBalance < input.minimum) {
    return { decision: "REJECT", reason: "THRESHOLD_MISMATCH" };
  }
  if (input.currentBlock >= input.expiryBlock) {
    return { decision: "REJECT", reason: "EXPIRED_CONDITION" };
  }
  if (normaliseHex(input.recipient) !== normaliseHex(input.conditionRecipient)) {
    return { decision: "REJECT", reason: "RECIPIENT_MISMATCH" };
  }
  if (input.amount > input.maxTransfer) {
    return { decision: "REJECT", reason: "AMOUNT_OVERFLOW" };
  }
  return { decision: "APPROVE", reason: "VALID_CONDITION" };
}

function toBigIntField(v: unknown, label: string): bigint {
  if (typeof v === "number" || typeof v === "bigint") return decToField(v);
  if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return decToField(v.trim());
  throw new Error(`field ${label} is not an integer: ${String(v)}`);
}

/**
 * Validate and normalise the raw `input` object of an envelope.
 * Throws on any malformed field; the caller turns that into REJECT/INVALID_TASK.
 */
export function parseInput(raw: unknown): GatekeeperInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("input is not an object");
  }
  const o = raw as Record<string, unknown>;
  for (const key of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"]) {
    if (!isHexString(o[key])) throw new Error(`field ${key} is not a hex string`);
  }
  for (const key of ["minimum", "public_balance", "expiry_block", "current_block", "amount", "max_transfer"]) {
    if (o[key] === undefined || o[key] === null) throw new Error(`field ${key} is missing`);
  }
  return {
    registeredVk: o.registered_vk as string,
    proofVk: o.proof_vk as string,
    minimum: toBigIntField(o.minimum, "minimum"),
    publicBalance: toBigIntField(o.public_balance, "public_balance"),
    expiryBlock: toBigIntField(o.expiry_block, "expiry_block"),
    currentBlock: toBigIntField(o.current_block, "current_block"),
    recipient: o.recipient as string,
    conditionRecipient: o.condition_recipient as string,
    amount: toBigIntField(o.amount, "amount"),
    maxTransfer: toBigIntField(o.max_transfer, "max_transfer"),
    proofTx: o.proof_tx as string,
  };
}

/**
 * Convert a validated input + decision into the 13 circuit input signals,
 * in circuit order. `taskIdField` is SHA-256(task_id) mod p and `salt` is the
 * private per-task salt; both are supplied by the caller.
 */
export function toCircuitSignals(
  input: GatekeeperInput,
  taskIdField: bigint,
  salt: bigint,
  decision: Decision,
): Record<string, string> {
  const s = (x: bigint) => x.toString(10);
  return {
    taskId: s(taskIdField),
    registeredVkHash: s(hexToField(input.registeredVk)),
    proofVkHash: s(hexToField(input.proofVk)),
    minimum: s(input.minimum),
    publicBalance: s(input.publicBalance),
    expiryBlock: s(input.expiryBlock),
    currentBlock: s(input.currentBlock),
    recipient: s(hexToField(input.recipient)),
    conditionRecipient: s(hexToField(input.conditionRecipient)),
    amount: s(input.amount),
    maxTransfer: s(input.maxTransfer),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: s(salt),
  };
}
