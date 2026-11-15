// HTTP server — the public endpoint the platform POSTs turns to.
// Uses Node's built-in http (no framework) so the service has a tiny
// dependency surface. TLS is terminated by the reverse proxy in front of
// it (the platform requires a public HTTPS endpoint).
//
// Flow for every POST to the agent path:
//   1. Read the RAW body (no parsing yet).
//   2. Verify x-agent-games-signature (HMAC over the raw body) BEFORE
//      parsing JSON. Mismatch -> 401, no work done.
//   3. Parse JSON. Preflight -> { ok: true, protocolVersion: "v1" }.
//      Turn envelope -> validate, check the frozen commitment, compute the
//      policy action, generate the Groth16 proof locally, verify it
//      locally, sign and return. Kurier submission is optional and never
//      blocks the response.
//   4. Every response is signed: x-agent-games-signature over the raw
//      response body.
//   5. Hard deadline (default 240s, platform allows 5 min per turn). On
//      timeout or ANY error -> signed HOLD with NO proof and NO amount.
//      Never crash into an invalid submission.
//
// Scoring note (from the event page): a timeout (no response) is -1/turn;
// a submitted-but-invalid proof is -2/turn. A HOLD response with no proof
// is resolved as HOLD. Responding is always better than hanging: a silent
// agent keeps forfeiting while the opponent extracts against its forced
// HOLDs, and repeated health-check failures can remove the agent from
// pairing.
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { config } from "./config.js";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac.js";
import { computeCommitmentHex } from "./commitment.js";
import {
  buildCircuitInputs,
  circuitVersionNumber,
  generateProof,
  parseField,
  verifyProofLocally,
} from "./circuit.js";
import { computePublicInputsHash } from "./hash.js";
import { submitProof, waitForFinalized } from "./kurier.js";
import { STRATEGY_PARAMS, policy, validateAction, type Action } from "./policy.js";
import { SeenSet } from "./seen.js";

const seen = new SeenSet();

function log(msg: string): void {
  // Never log secrets, the salt, or the strategy params. matchId + turn +
  // action + reason only. The commitment HASH is public (it is registered
  // on the dashboard), so logging it is safe.
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function readRawBody(req: IncomingMessage, limitBytes = 1_000_000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > limitBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": raw.length,
    [SIGNATURE_HEADER]: signBody(config.hmacSecret, raw),
  });
  res.end(raw);
}

function sendUnsignedJson(res: ServerResponse, status: number, body: unknown): void {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, { "content-type": "application/json", "content-length": raw.length });
  res.end(raw);
}

// --- Envelope types (per https://agentgames.zkverify.io/build) ---

export interface TurnEnvelope {
  protocolVersion: string;
  eventId: string;
  mode: string;
  matchId: string;
  turn: number;
  issuedAt: string;
  deadlineAt: string;
  state: {
    selfBalance: string | number;
    opponentBalance: string | number;
    selfFortifiedUntilTurn: number | null;
    opponentFortifiedUntilTurn: number | null;
  };
  strategyCommitment: { hash: string };
  resolverVersion: string;
  nonce: string;
}

interface TurnResponse {
  matchId: string;
  turn: number;
  action: Action;
  policyProof: {
    circuitVersion: string;
    proof?: unknown;
    public_signals?: string[];
    proofReference?: string;
    publicInputsHash?: string;
  };
  agentTimestamp: string;
  idempotencyKey: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Deterministic idempotency key for a turn: UUID-formatted SHA-256 of
 * "matchId:turn". A retried push gets the SAME key, so the platform
 * dedupes it ("only the first submission per key is accepted") instead of
 * treating the retry as a second submission. The key is a dedup token,
 * not a secret.
 */
function idempotencyKeyFor(matchId: string, turn: number): string {
  const hex = createHash("sha256").update(`${matchId}:${turn}`, "utf8").digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** The fail-closed response: HOLD, no proof, no amount. Always signed. */
function holdResponse(matchId: string, turn: number): TurnResponse {
  return {
    matchId,
    turn,
    action: { type: "HOLD" },
    policyProof: { circuitVersion: config.circuitVersion },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKeyFor(matchId, turn),
  };
}

// --- Local commitment (cached after first computation) ---

let cachedCommitmentHex: string | null = null;
let cachedCommitment: bigint | null = null;

async function localCommitment(): Promise<{ hex: string; value: bigint }> {
  if (cachedCommitmentHex && cachedCommitment !== null) {
    return { hex: cachedCommitmentHex, value: cachedCommitment };
  }
  const salt = parseField(config.strategySalt);
  const hex = await computeCommitmentHex(STRATEGY_PARAMS, salt);
  cachedCommitmentHex = hex;
  cachedCommitment = parseField(hex);
  log(`local commitment ${hex} (register this hash on the dashboard)`);
  return { hex, value: cachedCommitment };
}

/** Validate the envelope shape + timestamps. Returns an error string or null. */
function validateEnvelope(env: TurnEnvelope, nowMs: number): string | null {
  if (env.protocolVersion !== "v1") return "BAD_PROTOCOL_VERSION";
  if (env.eventId !== "steal-the-vfy") return "WRONG_EVENT";
  if (typeof env.matchId !== "string" || !UUID_RE.test(env.matchId)) return "BAD_MATCH_ID";
  if (!Number.isInteger(env.turn) || env.turn < 0 || env.turn > 20) return "BAD_TURN";
  const s = env.state;
  if (!s || typeof s !== "object") return "BAD_STATE";
  const self = Number(s.selfBalance);
  const opp = Number(s.opponentBalance);
  if (!Number.isFinite(self) || self < 0 || !Number.isFinite(opp) || opp < 0) {
    return "BAD_BALANCE";
  }
  const issued = Date.parse(env.issuedAt);
  if (Number.isFinite(issued) && nowMs - issued > config.turnMaxAgeMs) return "STALE_TURN";
  const deadline = Date.parse(env.deadlineAt);
  if (Number.isFinite(deadline) && deadline <= nowMs) return "TURN_EXPIRED";
  if (!env.strategyCommitment || typeof env.strategyCommitment.hash !== "string") {
    return "MISSING_COMMITMENT";
  }
  return null;
}

/** Handle one turn envelope. Runs inside the hard deadline. */
async function handleTurn(env: TurnEnvelope): Promise<TurnResponse> {
  const started = Date.now();
  const { matchId, turn } = env;
  const timeLeft = () => config.responseDeadlineMs - (Date.now() - started);

  // Idempotency: never answer the same (matchId, turn) twice. Every
  // answered turn (including fail-closed HOLDs) is recorded, so a retried
  // push is recognised as a duplicate and answered HOLD again instead of
  // generating a second proof for the same turn.
  const seenKey = `${matchId}:${turn}`;
  const failClosed = (reason: string): TurnResponse => {
    seen.add(seenKey);
    log(`${matchId} turn ${turn} HOLD ${reason}`);
    return holdResponse(matchId, turn);
  };

  // 1. Validate envelope shape + timestamps.
  const envelopeErr = validateEnvelope(env, Date.now());
  if (envelopeErr) {
    return failClosed(envelopeErr);
  }

  if (seen.has(seenKey)) {
    return failClosed("DUPLICATE_TURN");
  }

  // 3. The frozen commitment is authoritative: the envelope hash must
  //    match the commitment computed from our own params + salt.
  let commitment: { hex: string; value: bigint };
  try {
    commitment = await localCommitment();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return failClosed(`COMMITMENT_ERROR ${msg.slice(0, 120)}`);
  }
  if (env.strategyCommitment.hash.toLowerCase() !== commitment.hex.toLowerCase()) {
    return failClosed("COMMITMENT_MISMATCH");
  }

  // 4. Deterministic policy action for this state.
  const state = {
    selfBalance: Number(env.state.selfBalance),
    opponentBalance: Number(env.state.opponentBalance),
    selfFortifiedUntilTurn: env.state.selfFortifiedUntilTurn,
    opponentFortifiedUntilTurn: env.state.opponentFortifiedUntilTurn,
    turn,
  };
  let action: Action;
  try {
    action = policy(state, STRATEGY_PARAMS);
    validateAction(action);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return failClosed(`POLICY_ERROR ${msg.slice(0, 120)}`);
  }

  // 5. Build circuit inputs + the public-inputs hash (audit field).
  const versionNum = circuitVersionNumber(config.circuitVersion);
  const salt = parseField(config.strategySalt);
  const inputs = buildCircuitInputs({
    commitment: commitment.value,
    matchId,
    turn,
    selfBalance: state.selfBalance,
    opponentBalance: state.opponentBalance,
    action,
    circuitVersion: versionNum,
    salt,
    strategyParams: STRATEGY_PARAMS,
  });
  const publicInputsHash = computePublicInputsHash({
    commitment: commitment.hex,
    matchId,
    turn,
    selfBalance: state.selfBalance,
    opponentBalance: state.opponentBalance,
    action,
    circuitVersion: versionNum,
  });

  // 6. Generate the proof locally, bounded by PROOF_TIMEOUT_MS.
  //    A wrong action makes the witness refuse — that is the circuit
  //    acting as referee, and it surfaces here as a fail-closed HOLD.
  let proof: unknown;
  let publicSignals: string[];
  try {
    const budget = Math.min(config.proofTimeoutMs, Math.max(1000, timeLeft() - 5000));
    const result = await generateProof(inputs, budget);
    proof = result.proof;
    publicSignals = result.publicSignals;
    log(`${matchId} turn ${turn} ${action.type}${action.amount ? ` ${action.amount}` : ""} prove ${result.proveMs}ms`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return failClosed(`PROOF_FAILED ${msg.slice(0, 150)}`);
  }

  // 7. The proof must verify locally before we trust it.
  let locallyValid = false;
  try {
    locallyValid = await verifyProofLocally(proof, publicSignals);
  } catch {
    locallyValid = false;
  }
  if (!locallyValid) {
    return failClosed("PROOF_INVALID (local verify failed)");
  }

  // 8. OPTIONAL Kurier submission (audit pointer only). Never block the
  //    turn on it: race finalization against a short grace window, then
  //    respond with or without the proofReference.
  let proofReference: string | undefined;
  try {
    if (config.kurierApiKey) {
      const grace = Math.min(10000, Math.max(0, timeLeft() - 2000));
      if (grace > 3000) {
        const finalize = (async () => {
          const { jobId } = await submitProof(proof, publicSignals, config.registeredVkHash);
          return waitForFinalized(jobId, grace);
        })();
        const raced = await Promise.race([
          finalize,
          new Promise<null>((resolve) => setTimeout(() => resolve(null), grace)),
        ]);
        if (raced) {
          proofReference = raced;
          log(`${matchId} turn ${turn} kurier finalized ${raced.slice(0, 18)}...`);
        }
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`${matchId} turn ${turn} kurier skipped: ${msg.slice(0, 120)}`);
  }

  // 9. Mark the turn answered and return the signed response.
  seen.add(seenKey);
  const response: TurnResponse = {
    matchId,
    turn,
    action,
    policyProof: {
      circuitVersion: config.circuitVersion,
      proof,
      public_signals: publicSignals,
      ...(proofReference ? { proofReference } : {}),
      publicInputsHash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKeyFor(matchId, turn),
  };
  return response;
}

async function handlePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const started = Date.now();
  let raw: Buffer;
  try {
    raw = await readRawBody(req);
  } catch {
    sendUnsignedJson(res, 413, { error: "body too large" });
    return;
  }

  // 1. HMAC BEFORE parsing. A mismatch is rejected with no further work.
  const sig = req.headers[SIGNATURE_HEADER];
  if (!verifySignature(config.hmacSecret, raw, sig)) {
    log(`POST ${config.agentPath} REJECT INVALID_SIGNATURE`);
    sendUnsignedJson(res, 401, { error: "invalid signature" });
    return;
  }

  // 2. Parse JSON.
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { error: "malformed envelope" });
    return;
  }

  // 3. Preflight: the platform's handshake before any turn.
  //    (Format assumed from the Proof Gatekeeper standard; the Steal the
  //    VFY /build page does not publish a distinct preflight shape.)
  if (body.type === "agent-games.preflight.v1") {
    log(`preflight ok (agent_id=${String(body.agent_id ?? "?")})`);
    sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    return;
  }

  // 4. Turn envelope.
  if (body.eventId === "steal-the-vfy" || body.protocolVersion === "v1") {
    const env = body as unknown as TurnEnvelope;
    const hasEcho = typeof env.matchId === "string" && typeof env.turn === "number";
    // Hard deadline: race the handler against the remaining budget.
    const budget = Math.max(1000, config.responseDeadlineMs - (Date.now() - started));
    const timeout = new Promise<TurnResponse>((resolve) =>
      setTimeout(() => {
        if (hasEcho) resolve(holdResponse(env.matchId, env.turn));
        else resolve(holdResponse("", 0));
      }, budget),
    );
    const result = await Promise.race([handleTurn(env), timeout]);
    if (hasEcho) {
      sendJson(res, 200, result);
    } else {
      sendJson(res, 400, { error: "malformed envelope" });
    }
    return;
  }

  sendJson(res, 400, { error: "malformed envelope" });
}

export function createHttpServer() {
  return createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        sendUnsignedJson(res, 200, {
          ok: true,
          protocolVersion: "v1",
          seenTurns: seen.size,
        });
        return;
      }
      if (req.method === "POST" && req.url === config.agentPath) {
        await handlePost(req, res);
        return;
      }
      sendUnsignedJson(res, 404, { error: "not found" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`unhandled error: ${msg.slice(0, 200)}`);
      if (!res.headersSent) {
        sendUnsignedJson(res, 500, { error: "internal error" });
      }
    }
  });
}
