# 0xrnld-gatekeeper

HTTPS agent endpoint for the **Proof Gatekeeper** event in the zkVerify
Agent Games. The platform POSTs HMAC-signed task envelopes; this service
verifies the signature, makes a deterministic APPROVE/REJECT decision,
generates a real Groth16 proof locally with snarkjs against the official
gatekeeper circuit, optionally submits it to zkVerify via Kurier, and
returns a signed response — well inside the 60-second hard deadline
(typical end-to-end: ~0.3–1.6 s).

Written from scratch for the Agent Games spec. The reference agent's repo
has no license, so no code was adapted from it; the protocol facts here
were verified independently against the published circuit artifacts.

## How it works

```
POST /agent
  │
  ├─ 1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed `{ ok: true, protocolVersion: "v1" }`
  └─ 3. type = "agent-games.proof-gatekeeper.v1"
        ├─ idempotency cache (same task_id → cached response bytes)
        ├─ deterministic policy → decision + reason_code
        ├─ snarkjs fullProve with gatekeeper.wasm / gatekeeper_final.zkey
        │    (skipped only for PROOF_REUSED — those tasks have no proof)
        ├─ Kurier submit + bounded poll (≤15 s) → on-chain txHash as proof_tx
        └─ signed JSON response
```

Fail closed throughout: malformed envelopes, internal errors, and proof
generation failures all resolve to REJECT, never to an unproven APPROVE.
The circuit asserts `decision == (all five field checks)`, so a wrong
decision is unprovable — the circuit is the referee.

## Decision rules (boundaries inclusive)

APPROVE only if **all** hold: `proof_vk == registered_vk`, `proof_tx`
never seen before, `public_balance >= minimum`,
`current_block < expiry_block`, `recipient == condition_recipient`,
`amount <= max_transfer`. One failed check → REJECT with:

| reason_code          | meaning                        |
| -------------------- | ------------------------------ |
| `VALID_CONDITION`    | approved                       |
| `VK_SUBSTITUTION`    | proof_vk differs from registered_vk |
| `PROOF_REUSED`       | proof_tx was already used (no proof returned) |
| `THRESHOLD_MISMATCH` | public_balance < minimum       |
| `EXPIRED_CONDITION`  | current_block >= expiry_block  |
| `RECIPIENT_MISMATCH` | recipient differs from condition_recipient |
| `AMOUNT_OVERFLOW`    | amount > max_transfer          |
| `INVALID_TASK`       | local fallback for malformed envelopes / internal errors |

## The circuit — verified signal layout (read this)

The /build text says the 13 public signals are
"[Poseidon(taskId, salt), then the 12 public inputs in order]". That
description is **inaccurate in two places**, verified empirically against
the published artifacts on 15 Nov 2026 by probing the WASM's input-signal
oracle (FNV-1a hash) and proving with distinct values for every input:

- Public signal 0 is **Poseidon(salt, taskId)** — salt FIRST, taskId
  second. (For (1,1) both orders agree, which is why this is easy to miss.)
- The 12 remaining signals are, in order: `registeredVkHash`,
  `proofVkHash`, `minimum`, `publicBalance`, `expiryBlock`,
  `currentBlock`, `recipient`, `conditionRecipient`, `amount`,
  `maxTransfer`, `decision`, and **`taskId` last** — taskId is signal 12,
  not signal 1.

The full verified layout (see `src/prover.ts`):

```
[0]  Poseidon(salt, taskId)
[1]  registeredVkHash   [2]  proofVkHash      [3]  minimum
[4]  publicBalance      [5]  expiryBlock      [6]  currentBlock
[7]  recipient          [8]  conditionRecipient
[9]  amount             [10] maxTransfer      [11] decision
[12] taskId (SHA-256(task_id) mod p)
```

Circuit inputs (13, all size 1): `taskId`, `registeredVkHash`,
`proofVkHash`, `minimum`, `publicBalance`, `expiryBlock`, `currentBlock`,
`recipient`, `conditionRecipient`, `amount`, `maxTransfer`, `decision`,
`salt` (private). Field elements are envelope values reduced mod the
BN128 prime; `salt = HMAC(secret, "gatekeeper-salt:" + task_id) mod p`,
so a redelivered task reproduces identical proof inputs.

## Setup

```bash
npm install
npm run fetch-circuits   # gatekeeper.wasm + gatekeeper_final.zkey into circuits/
cp .env.example .env     # fill in the secrets (never commit .env)
npm test                 # boots the real server, replays spec envelopes
npm run build && npm start
```

`GET /agent` is the health check. `POST /agent` is the signed endpoint.

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | From the Agent Games dashboard (agent → **Rotate Secret**); shown once. Never a local placeholder. |
| `KURIER_API_KEY` | no | Mainnet Kurier key (https://kurier.xyz). If unset, submission is skipped gracefully and the agent still answers with proof + public signals. |
| `KURIER_API_URL` | no | Default `https://api.kurier.xyz/api/v1`. |
| `GATEKEEPER_VK_HASH` | no | Defaults to `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`. |
| `KURIER_POLL_BUDGET_MS` | no | Default 15000. |
| `TASK_SOFT_DEADLINE_MS` | no | Default 50000 (hard platform deadline is 60 s). |
| `SEEN_STORE_PATH` | no | Default `data/seen.json` locally, `/tmp/…` on Vercel. |
| `CIRCUITS_DIR`, `PORT` | no | Artifact location override; local port (default 8787). |

## Kurier submission

`POST /submit-proof/{API_KEY}` with `{ proofType: "groth16",
vkRegistered: true, proofOptions: { library: "snarkjs", curve: "bn128" },
proofData: { proof, publicSignals, vk } }`, then polls
`GET /job-status/{API_KEY}/{jobId}` until the status reaches `Submitted`
(txHash exists, ~4 s live). It never waits for `Finalized` inside the
60 s window — finalization continues server-side at Kurier. Status flow:
`Queued → Valid → Submitted → IncludedInBlock → Finalized` (or `Failed`).
When no key is configured, `proof_tx` in the response echoes the task's
input `proof_tx`.

## Registration & preflight flow

1. Deploy (Vercel: connect the repo and deploy; the build fetches the
   circuit artifacts — see `vercel.json` — or run `npm run build &&
   npm start` on any Node ≥ 18 host).
2. Register the full handler path — `https://<host>/agent`, not the root —
   in the Agent Games dashboard.
3. Dashboard → **Rotate Secret** → set the revealed plaintext as
   `AGENT_GAMES_HMAC_SECRET` → redeploy/restart.
4. The platform sends a signed preflight (`type:
   agent-games.preflight.v1`); this agent answers `{ ok: true,
   protocolVersion: "v1" }` signed, and the dashboard marks the agent
   active. `GET /agent` also serves as the health check.
5. Complete at least one practice task before scored rounds.

## Local test results

`npm test` boots the real server and replays spec-shaped envelopes —
**67/67 checks pass**, including:

- HMAC roundtrip (hex + base64 + `sha256=` acceptance),
  tamper / wrong-secret / missing → 401
- Preflight body shape + valid response signature
- Valid task → APPROVE / VALID_CONDITION, proof **verified locally**
  with `snarkjs groth16 verify` against the extracted verification key,
  public signals matching the verified layout above
- All six traps → correct REJECT + reason_code, each proof verified
  (PROOF_REUSED correctly carries no proof)
- Boundary inclusivity: balance == minimum, amount == max_transfer,
  current_block == expiry_block − 1 all approve
- Idempotent redelivery (cached response bytes, not misread as reuse)
- Circuit-as-referee: witness generation fails for decision=1 on a
  trapped statement and for decision=0 on a valid one
- Seen-set + response cache survive a reload from disk
- Response times: ~1.6 s cold (incl. WASM load), ~0.32–0.40 s warm

## Deployment notes

- **Seen-set durability:** the seen-set lives in process memory + a JSON
  file. On Vercel the file is in `/tmp` and state can reset on cold
  start; within a round, warm instances retain it. For maximum
  PROOF_REUSED reliability across rounds, a single long-lived instance
  (`npm start` on a small VM/container) is the safer host.
- The `circuits/gatekeeper.wasm` and `gatekeeper_final.zkey` files are
  binary platform artifacts and are NOT committed; the Vercel build
  downloads them (`scripts/fetch-circuits.js`). The verification key
  (`circuits/verification_key.json`, extracted from the zkey) IS
  committed, for local proof verification.

## File layout

| Path | Purpose |
| --- | --- |
| `api/agent.ts` | Vercel serverless entry (`bodyParser: false` → raw body for HMAC). |
| `src/server.ts` | Long-lived entry (`npm start`). |
| `src/httpServer.ts` | Plain Node HTTP server (GET health, POST /agent). |
| `src/handler.ts` | Framework-agnostic request pipeline shared by both entries. |
| `src/hmac.ts` | HMAC sign/verify + per-task circuit salt derivation. |
| `src/policy.ts` | Deterministic policy + envelope→circuit field conversion. |
| `src/field.ts` | BN128 field arithmetic (mod p reduction, hash/address parsing). |
| `src/prover.ts` | snarkjs `groth16.fullProve` wrapper + Poseidon binding. |
| `src/kurier.ts` | Kurier submit-proof + job-status polling (never throws). |
| `src/store.ts` | proof_tx seen-set + response cache, JSON-file backed. |
| `src/config.ts` | Environment configuration. |
| `scripts/fetch-circuits.js` | Downloads the official circuit artifacts. |
| `circuits/` | `gatekeeper.wasm`, `gatekeeper_final.zkey` (fetched, not committed), `verification_key.json` (committed). |
| `test/harness.ts` | Local end-to-end harness (`npm test`). |
