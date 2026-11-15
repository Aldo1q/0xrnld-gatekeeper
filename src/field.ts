// Field arithmetic for the BN128 (alt_bn128) scalar field used by the
// gatekeeper circuit. Every envelope value that enters the circuit is
// reduced modulo the field prime first: a 32-byte hash does not fit the
// field, and reduction preserves the equality checks the circuit performs.
import { createHash } from "node:crypto";

export const FIELD_PRIME =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export function modField(x: bigint): bigint {
  const r = x % FIELD_PRIME;
  return r >= 0n ? r : r + FIELD_PRIME;
}

/** Parse a 0x-prefixed (or bare) hex string into a field element. */
export function hexToField(hex: string): bigint {
  if (typeof hex !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`not a hex value: ${String(hex)}`);
  }
  return modField(BigInt(hex.startsWith("0x") ? hex : "0x" + hex));
}

/** Parse a decimal string / number / bigint into a field element. */
export function decToField(v: string | number | bigint): bigint {
  if (typeof v === "bigint") return modField(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error(`not an integer: ${v}`);
    return modField(BigInt(v));
  }
  if (typeof v === "string" && /^-?\d+$/.test(v.trim())) {
    return modField(BigInt(v.trim()));
  }
  throw new Error(`not a decimal integer: ${String(v)}`);
}

/** SHA-256 of a UTF-8 string, reduced into the field. Used for taskId. */
export function hashStringToField(s: string): bigint {
  const digest = createHash("sha256").update(s, "utf8").digest();
  return modField(BigInt("0x" + digest.toString("hex")));
}

/** Raw bytes (e.g. an HMAC digest) reduced into the field. */
export function bytesToField(b: Buffer): bigint {
  return modField(BigInt("0x" + b.toString("hex")));
}

/** Normalise an address / hash for equality checks (lowercase, 0x-prefixed). */
export function normaliseHex(hex: string): string {
  const h = String(hex).toLowerCase();
  return h.startsWith("0x") ? h : "0x" + h;
}

export function isHexString(v: unknown): v is string {
  return typeof v === "string" && /^(0x)?[0-9a-fA-F]+$/.test(v);
}
