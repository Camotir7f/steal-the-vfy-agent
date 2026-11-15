// Configuration — all secrets come from the environment only.
// Never hardcode a secret here. See .env.example.
import { readFileSync } from "node:fs";

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.trim() === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v;
}

function optional(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.trim() !== "" ? v : fallback;
}

function optionalInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v || v.trim() === "") return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

// Load a .env file if present (dev convenience only — production sets real
// environment variables). This parser is intentionally tiny and never logs
// values.
function loadDotEnv(): void {
  try {
    const text = readFileSync(".env", "utf8");
    for (const line of text.split("\n")) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2].trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!(key in process.env)) process.env[key] = val;
    }
  } catch {
    // No .env file — rely on real environment variables.
  }
}

loadDotEnv();

export const config = {
  // HMAC secret from the dashboard ("Rotate Secret"). Shown once.
  hmacSecret: required("AGENT_GAMES_HMAC_SECRET"),
  // Kurier API key (testnet.kurier.xyz / kurier.xyz). The turn response
  // never waits on Kurier, so a placeholder key only loses the optional
  // proofReference pointer.
  kurierApiKey: optional("KURIER_API_KEY", ""),
  // Private strategy salt (decimal or 0x-hex field element). Never logged.
  strategySalt: required("STRATEGY_SALT"),
  // "testnet" | "mainnet". Start on testnet.
  kurierNetwork: optional("KURIER_NETWORK", "testnet").toLowerCase(),
  port: optionalInt("PORT", 3000),
  agentPath: optional("AGENT_PATH", "/agent"),
  // The registered vfy-policy verification-key hash (from /api/circuit-info).
  registeredVkHash: optional(
    "REGISTERED_VK_HASH",
    "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
  ).toLowerCase(),
  // Circuit version string ("v1" -> 1 in the circuit inputs).
  circuitVersion: optional("CIRCUIT_VERSION", "v1"),
  // Hard response deadline (platform allows 5 min per turn).
  responseDeadlineMs: optionalInt("RESPONSE_DEADLINE_MS", 240000),
  // Max time for one local Groth16 proof before failing closed to HOLD.
  proofTimeoutMs: optionalInt("PROOF_TIMEOUT_MS", 120000),
  // Max time to wait for a Kurier job to reach Finalized.
  kurierFinalizeTimeoutMs: optionalInt("KURIER_FINALIZE_TIMEOUT_MS", 30000),
  // Max age of a turn's issuedAt (clock-skew guard).
  turnMaxAgeMs: optionalInt("TURN_MAX_AGE_MS", 300000),
  // Circuit artifact paths.
  wasmPath: optional("VFY_WASM", "circuits/vfy-policy.wasm"),
  zkeyPath: optional("VFY_ZKEY", "circuits/vfy-policy_final.zkey"),
  vkeyPath: optional("VFY_VKEY", "circuits/verification_key.json"),
  // Persistent seen-set for turn idempotency (matchId:turn).
  seenDbPath: optional("SEEN_DB_PATH", "data/seen.json"),
} as const;

export function kurierBaseUrl(): string {
  return config.kurierNetwork === "mainnet"
    ? "https://api.kurier.xyz/api/v1"
    : "https://api-testnet.kurier.xyz/api/v1";
}
