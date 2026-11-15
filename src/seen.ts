// Turn idempotency seen-set — remembers every (matchId, turn) pair this
// agent has already answered, so a retried push is never answered twice
// with a fresh proof (the platform accepts only the first submission per
// idempotencyKey). Persisted to disk so a restart does not forget.
// The key is `${matchId}:${turn}`.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "./config.js";

export class SeenSet {
  private set = new Set<string>();

  constructor(private path: string = config.seenDbPath) {
    this.load();
  }

  private load(): void {
    try {
      const raw = readFileSync(this.path, "utf8");
      const arr = JSON.parse(raw) as string[];
      if (Array.isArray(arr)) for (const v of arr) if (typeof v === "string") this.set.add(v);
    } catch {
      // No file yet — start empty.
    }
  }

  private save(): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, JSON.stringify([...this.set], null, 2));
    } catch {
      // Persistence is best-effort; the in-memory set still protects this run.
    }
  }

  has(key: string): boolean {
    return this.set.has(key);
  }

  add(key: string): void {
    if (!key) return;
    this.set.add(key);
    this.save();
  }

  get size(): number {
    return this.set.size;
  }
}
