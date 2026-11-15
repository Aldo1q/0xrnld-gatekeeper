// Kurier submission to zkVerify mainnet.
// Flow (zkVerify docs): POST /submit-proof/{API_KEY} -> { jobId }.
// Poll GET /job-status/{API_KEY}/{jobId} until the status reaches
// `Submitted` (txHash exists, ~4 s live) — never wait for `Finalized`
// inside the platform's 60 s window; finalization continues server-side
// at Kurier. Status flow: Queued -> Valid -> Submitted -> IncludedInBlock
// -> Finalized (or Failed). Never throws: every failure degrades to
// "not submitted" and the agent still answers with proof + public signals.
import type { GeneratedProof } from "./prover";

export interface KurierSettings {
  apiKey: string | undefined;
  apiUrl: string;
  vkHash: string;
  pollBudgetMs: number;
}

export interface KurierOutcome {
  submitted: boolean;
  txHash: string | undefined;
  jobId: string | undefined;
  status: string | undefined;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function pickString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

export async function submitToKurier(
  settings: KurierSettings,
  proof: GeneratedProof["proof"],
  publicSignals: string[],
  startedAtMs: number,
  softDeadlineMs: number,
): Promise<KurierOutcome> {
  const notSubmitted: KurierOutcome = { submitted: false, txHash: undefined, jobId: undefined, status: undefined };
  if (!settings.apiKey) return notSubmitted;

  let jobId: string | undefined;
  try {
    const res = await fetch(`${settings.apiUrl}/submit-proof/${settings.apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: settings.vkHash },
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return notSubmitted;
    const data = asRecord(await res.json());
    if (!data) return notSubmitted;
    jobId =
      pickString(data, ["jobId", "job_id", "id"]) ??
      pickString(asRecord(data.job) ?? {}, ["jobId", "job_id", "id"]);
    if (!jobId) return notSubmitted;
  } catch {
    return notSubmitted;
  }

  // Bounded poll for the Submitted stage. The remaining budget is the
  // smaller of the configured poll budget and the time left before the
  // platform's soft deadline, so we never blow the 60 s window.
  const pollEnd = Math.min(
    startedAtMs + settings.pollBudgetMs,
    startedAtMs + Math.max(0, softDeadlineMs - 3000),
  );
  let lastStatus: string | undefined;
  let txHash: string | undefined;
  while (Date.now() < pollEnd) {
    try {
      const res = await fetch(
        `${settings.apiUrl}/job-status/${settings.apiKey}/${encodeURIComponent(jobId)}`,
        { signal: AbortSignal.timeout(5000) },
      );
      if (res.ok) {
        const data = asRecord(await res.json());
        if (data) {
          const status = pickString(data, ["status", "state"]) ?? pickString(asRecord(data.job) ?? {}, ["status", "state"]);
          if (status) lastStatus = status;
          txHash =
            pickString(data, ["txHash", "tx_hash", "transactionHash", "tx"]) ??
            pickString(asRecord(data.job) ?? {}, ["txHash", "tx_hash", "transactionHash", "tx"]);
          if (txHash) {
            return { submitted: true, txHash, jobId, status: lastStatus };
          }
          if (lastStatus === "Submitted" || lastStatus === "IncludedInBlock" || lastStatus === "Finalized") {
            // Status reached a stage where a tx exists even if the hash field
            // was not in this payload shape; one more short wait, then give up.
            await sleep(500);
          }
          if (lastStatus === "Failed") return { submitted: false, txHash: undefined, jobId, status: lastStatus };
        }
      }
    } catch {
      /* transient: retry until the budget runs out */
    }
    await sleep(1000);
  }
  return { submitted: txHash !== undefined, txHash, jobId, status: lastStatus };
}
