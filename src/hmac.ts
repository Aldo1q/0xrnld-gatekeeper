// HMAC-SHA256 signing / verification over raw request bodies, plus the
// deterministic per-task circuit salt.
import { createHmac, timingSafeEqual } from "node:crypto";
import { bytesToField } from "./field";

/** Sign a raw body: returns the lowercase hex HMAC-SHA256. */
export function signBody(secret: string, body: Buffer): string {
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(body).digest("hex");
}

/**
 * Verify an inbound `x-agent-games-signature` header against the raw body.
 * Accepts the same MAC bytes encoded as hex or base64, with an optional
 * `sha256=` prefix. Comparison is constant-time; anything undecodable,
 * wrong-length, or mismatched is a failure.
 */
export function verifySignature(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  let value = header.trim();
  if (value.toLowerCase().startsWith("sha256=")) value = value.slice("sha256=".length);
  const expected = createHmac("sha256", Buffer.from(secret, "utf8")).update(body).digest();
  const candidates: Buffer[] = [];
  if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    try {
      candidates.push(Buffer.from(value, "hex"));
    } catch {
      /* not hex, fall through to base64 */
    }
  }
  try {
    const b64 = Buffer.from(value, "base64");
    // Reject base64 strings that round-trip to something else (e.g. plain hex
    // that also happens to be valid base64) only when they cannot be the MAC:
    // we keep both candidates and compare each.
    if (b64.length > 0) candidates.push(b64);
  } catch {
    /* not base64 */
  }
  for (const candidate of candidates) {
    if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) {
      return true;
    }
  }
  return false;
}

/**
 * Deterministic circuit salt for a task, so a redelivered task reproduces
 * identical proof inputs: HMAC(secret, "gatekeeper-salt:" + task_id) mod p.
 */
export function deriveSalt(secret: string, taskId: string): bigint {
  const mac = createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(`gatekeeper-salt:${taskId}`, "utf8")
    .digest();
  return bytesToField(mac);
}
