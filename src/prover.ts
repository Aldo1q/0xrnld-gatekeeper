// Groth16 proving against the official gatekeeper circuit with snarkjs,
// plus the Poseidon hash used for public signal 0.
import * as fs from "node:fs";
import * as path from "node:path";

// snarkjs and circomlibjs ship no TypeScript declarations; see snarkjs.d.ts.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";

export interface GeneratedProof {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
}

interface PoseidonInstance {
  (inputs: bigint[]): unknown;
  F: { toString: (x: unknown) => string };
}

// Poseidon singleton: building it costs ~1 s, so build once per process.
let poseidonPromise: Promise<PoseidonInstance> | null = null;

function getPoseidon(): Promise<PoseidonInstance> {
  if (!poseidonPromise) {
    poseidonPromise = buildPoseidon() as unknown as Promise<PoseidonInstance>;
  }
  return poseidonPromise;
}

/** Poseidon(a, b) — the circuit's 2-input Poseidon. */
export async function poseidon2(a: bigint, b: bigint): Promise<bigint> {
  const poseidon = await getPoseidon();
  const out = poseidon([a, b]);
  return BigInt(poseidon.F.toString(out));
}

/**
 * The task-binding hash the circuit emits as public signal 0.
 *
 * VERIFIED EMPIRICALLY (15 Nov 2026) against the official artifacts:
 * the circuit computes Poseidon(salt, taskId) — salt FIRST, taskId
 * second — NOT Poseidon(taskId, salt) as the /build text states.
 * (For (1,1) both orders agree, which is why this was easy to miss.)
 */
export async function taskBindingHash(salt: bigint, taskId: bigint): Promise<bigint> {
  return poseidon2(salt, taskId);
}

/**
 * VERIFIED public-signal layout of the gatekeeper circuit (15 Nov 2026,
 * from the artifacts, using distinct values for every input):
 *   [0]  Poseidon(salt, taskId)
 *   [1]  registeredVkHash
 *   [2]  proofVkHash
 *   [3]  minimum
 *   [4]  publicBalance
 *   [5]  expiryBlock
 *   [6]  currentBlock
 *   [7]  recipient
 *   [8]  conditionRecipient
 *   [9]  amount
 *   [10] maxTransfer
 *   [11] decision
 *   [12] taskId (SHA-256(task_id) mod p)
 * Note taskId comes LAST, not second — the /build text's claim
 * "[Poseidon(taskId,salt), then the 12 public inputs in order]" is
 * inaccurate on both the Poseidon argument order and the position of
 * taskId. The response must carry the circuit's exact order, because
 * that is what the verification key enforces.
 */
export const PUBLIC_SIGNAL_COUNT = 13;

export interface CircuitPaths {
  wasm: string;
  zkey: string;
  vk: string;
}

export function circuitPaths(circuitsDir: string): CircuitPaths {
  return {
    wasm: path.join(circuitsDir, "gatekeeper.wasm"),
    zkey: path.join(circuitsDir, "gatekeeper_final.zkey"),
    vk: path.join(circuitsDir, "verification_key.json"),
  };
}

export function circuitsPresent(circuitsDir: string): boolean {
  const p = circuitPaths(circuitsDir);
  return fs.existsSync(p.wasm) && fs.existsSync(p.zkey);
}

export function loadVerificationKey(circuitsDir: string): unknown {
  const p = circuitPaths(circuitsDir);
  return JSON.parse(fs.readFileSync(p.vk, "utf8"));
}

/**
 * Run snarkjs groth16 fullProve. Throws if witness generation fails — which
 * is exactly what happens when the decision does not match the circuit's own
 * evaluation of the five field checks (a wrong decision is unprovable).
 */
export async function prove(
  circuitInputs: Record<string, string>,
  circuitsDir: string,
): Promise<GeneratedProof> {
  const p = circuitPaths(circuitsDir);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    p.wasm,
    p.zkey,
  );
  const normalised: GeneratedProof["proof"] = {
    pi_a: (proof.pi_a as unknown[]).map(String),
    pi_b: (proof.pi_b as unknown[][]).map((row) => row.map(String)),
    pi_c: (proof.pi_c as unknown[]).map(String),
    protocol: "groth16",
    curve: "bn128",
  };
  return { proof: normalised, publicSignals: (publicSignals as unknown[]).map(String) };
}

export async function verifyProof(
  verificationKey: unknown,
  proof: GeneratedProof["proof"],
  publicSignals: string[],
): Promise<boolean> {
  return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
}
