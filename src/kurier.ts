// Kurier REST client — submit a Groth16 proof to zkVerify and poll until
// it reaches Finalized. Follows the official Kurier tutorial
// (docs.zkverify.io/overview/getting-started/kurier).
//
// Endpoints (base URL depends on network):
//   POST /submit-proof/{apiKey}
//     { proofType: "groth16", vkRegistered: true,
//       proofOptions: { library: "snarkjs", curve: "bn128" },
//       proofData: { proof, publicSignals, vk: <vkHash> } }
//     -> { jobId, optimisticVerify: "success" }
//   GET  /job-status/{apiKey}/{jobId}
//     -> { jobId, status, txHash, ... }
// Statuses: Queued, Valid, Submitted, IncludedInBlock, Finalized, Failed.
// Only "Finalized" counts as confirmed. Anything else -> no proof_tx.
//
// For Steal the VFY this is OPTIONAL: the turn response is verified
// offline from the raw proof in policyProof, and the platform never waits
// on Finalized. The server fires this in the background and only attaches
// the proofReference if it finalizes within a short grace window.
import { config, kurierBaseUrl } from "./config.js";

export interface SubmitResult {
  jobId: string;
  optimisticVerify?: string;
}

export interface JobStatus {
  jobId: string;
  status: string;
  txHash?: string | null;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const text = await res.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    if (!res.ok) {
      throw new Error(`Kurier HTTP ${res.status}: ${JSON.stringify(body)?.slice(0, 300)}`);
    }
    return body;
  } finally {
    clearTimeout(t);
  }
}

/** Submit a proof. The VK is already registered (vkRegistered: true). */
export async function submitProof(
  proof: unknown,
  publicSignals: string[],
  vkHash: string,
): Promise<SubmitResult> {
  const url = `${kurierBaseUrl()}/submit-proof/${config.kurierApiKey}`;
  const body = await fetchJson(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
      }),
    },
    15000,
  );
  const b = body as Record<string, unknown>;
  if (!b || typeof b.jobId !== "string") {
    throw new Error(`Kurier submit-proof returned no jobId: ${JSON.stringify(body)?.slice(0, 300)}`);
  }
  return { jobId: b.jobId, optimisticVerify: b.optimisticVerify as string | undefined };
}

/** Poll job-status until Finalized / Failed / timeout. Returns the txHash on Finalized. */
export async function waitForFinalized(
  jobId: string,
  timeoutMs: number,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const url = `${kurierBaseUrl()}/job-status/${config.kurierApiKey}/${jobId}`;
    let body: unknown;
    try {
      body = await fetchJson(url, { method: "GET" }, 10000);
    } catch {
      // Transient Kurier error — keep polling until the timeout.
      await sleep(2000);
      continue;
    }
    const s = body as JobStatus;
    if (s.status === "Finalized") return s.txHash ?? null;
    if (s.status === "Failed") return null;
    await sleep(3000);
  }
  return null;
}
