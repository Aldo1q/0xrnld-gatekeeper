// Durable idempotency: the proof_tx seen-set and the per-task response
// cache, mirrored in memory and persisted to a JSON file (atomic write via
// temp file + rename). The seen-set must survive restarts — a redelivered
// task returns its cached response, while a NEW task reusing an old
// proof_tx is PROOF_REUSED.
import * as fs from "node:fs";
import * as path from "node:path";

export interface SeenEntry {
  taskId: string;
  at: string;
}

export interface StoredResponse {
  body: string;
  at: string;
}

interface StoreFile {
  seen: Record<string, SeenEntry>;
  responses: Record<string, StoredResponse>;
}

export class SeenStore {
  private seen = new Map<string, SeenEntry>();
  private responses = new Map<string, StoredResponse>();
  private saveChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  load(): void {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw) as StoreFile;
      for (const [k, v] of Object.entries(data.seen ?? {})) this.seen.set(k, v);
      for (const [k, v] of Object.entries(data.responses ?? {})) this.responses.set(k, v);
    } catch {
      // Missing or corrupt file: start empty. A corrupt file is renamed aside
      // so it never blocks the agent.
      try {
        if (fs.existsSync(this.filePath)) {
          fs.renameSync(this.filePath, this.filePath + ".corrupt." + Date.now());
        }
      } catch {
        /* ignore */
      }
    }
  }

  hasProofTx(proofTx: string): boolean {
    return this.seen.has(proofTx.toLowerCase());
  }

  markProofTx(proofTx: string, taskId: string): void {
    this.seen.set(proofTx.toLowerCase(), { taskId, at: new Date().toISOString() });
    this.scheduleSave();
  }

  getCachedResponse(taskId: string): string | undefined {
    return this.responses.get(taskId)?.body;
  }

  setCachedResponse(taskId: string, body: string): void {
    this.responses.set(taskId, { body, at: new Date().toISOString() });
    this.scheduleSave();
  }

  get seenCount(): number {
    return this.seen.size;
  }

  get cachedCount(): number {
    return this.responses.size;
  }

  private scheduleSave(): void {
    this.saveChain = this.saveChain
      .then(() => this.saveNow())
      .catch(() => undefined);
  }

  /** Flush pending writes; used by tests and graceful shutdown. */
  async flush(): Promise<void> {
    await this.saveChain;
  }

  private saveNow(): void {
    const data: StoreFile = {
      seen: Object.fromEntries(this.seen),
      responses: Object.fromEntries(this.responses),
    };
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = this.filePath + ".tmp." + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(data), "utf8");
    fs.renameSync(tmp, this.filePath);
  }
}
