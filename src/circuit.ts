// vfy-policy circuit — input building, proof generation, local verification.
//
// Circuit facts (verified against the official artifacts, 2026-11-15):
// - Groth16 / BN128, compiled with Circom 2.x.
// - vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//   (from https://agentgames.zkverify.io/api/circuit-info, network mainnet).
// - 17 inputs, 9 public signals.
// - Input NAMES (verified: each name accepted by snarkjs wtns.calculate,
//   wrong names rejected with "Too many values"):
//     commitment, matchId, turnNumber, selfBalance, opponentBalance,
//     action, amount, circuitVersion, salt (9 single values)
//     + strategyParams (ARRAY of exactly 8 field elements).
//   NOTE: the input is "turnNumber" (not "turn"); "main.*" prefixes do NOT
//   work; "publicInputsHash" is NOT a circuit input.
// - commitment = Poseidon(strategyParams[0..7], salt) — params first, salt
//   last (see src/commitment.ts). The circuit asserts the commitment at
//   line 72.
// - Action encoding: HOLD=0, FORTIFY=1, EXTRACT=2. circuitVersion input = 1
//   for "v1". matchId = BigInt("0x" + uuid without hyphens) — the same
//   encoding as the publicInputsHash computation. Balances are plain
//   integers (e.g. 95, 105). turnNumber is the turn (e.g. 3).
// - Public signals, in snarkjs order (verified from a passing witness):
//     [ w1, commitment, matchId, turnNumber, selfBalance, opponentBalance,
//       action, amount, circuitVersion ]
//   w[0] (w1) is a circuit OUTPUT whose exact formula is UNDETERMINED — it
//   is NOT the keccak publicInputsHash and NOT a simple Poseidon of the
//   fields (12 combinations tested, none matched). The harness passes
//   public_signals through EXACTLY as snarkjs returns them; it does NOT
//   need to interpret w[0]. w[1] IS the commitment (verified: equals
//   Poseidon(params, salt)).
// - Policy semantics, PARTIALLY reversed (see src/policy.ts for the full
//   honest account): params[0] IS the EXTRACT amount — params [N,0,...]
//   accepts EXTRACT N (verified N=1,2,5,10) and refuses HOLD/FORTIFY
//   (assert line 140). The roles of params[1..7] are NOT documented and
//   were NOT fully reverse-engineered (asserts at lines 75, 76, 90, 140,
//   149, ...). Do not invent meanings for them.
//
// PROOF TIMING (measured 2026-11-15 on this VM): groth16.prove for the
// known-passing case took ~1.9 s and verified locally OK. An earlier
// attempt on the same VM ran 8+ minutes with no output and was killed —
// that run is unexplained (cold start / resource contention), so proof
// generation runs behind a configurable timeout (PROOF_TIMEOUT_MS, default
// 120 s) and the server fails closed to HOLD if it ever exceeds it.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import * as snarkjs from "snarkjs";
import { config } from "./config.js";
import { actionCode, validateAction, type Action } from "./policy.js";

export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Reduce a bigint into the BN128 scalar field. */
export function toField(v: bigint): bigint {
  const r = v % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

/** Parse a decimal or 0x-hex string into a field element. */
export function parseField(s: string | number | bigint): bigint {
  if (typeof s === "bigint") return toField(s);
  if (typeof s === "number") return toField(BigInt(s));
  const t = String(s).trim();
  return toField(t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t));
}

/** "v1" -> 1. The circuit takes the version as a small integer. */
export function circuitVersionNumber(version: string): number {
  const m = version.trim().match(/^v(\d+)$/i);
  if (!m) throw new Error(`Unsupported circuit version: ${version}`);
  return Number.parseInt(m[1], 10);
}

export interface CircuitInputs {
  commitment: string;
  matchId: string;
  turnNumber: string;
  selfBalance: string;
  opponentBalance: string;
  action: string;
  amount: string;
  circuitVersion: string;
  salt: string;
  strategyParams: string[];
}

/** Build the 17 circuit inputs for a turn + an action. */
export function buildCircuitInputs(args: {
  commitment: bigint;
  matchId: string; // UUID with hyphens
  turn: number;
  selfBalance: number;
  opponentBalance: number;
  action: Action;
  circuitVersion: number; // 1 for "v1"
  salt: bigint;
  strategyParams: readonly bigint[];
}): CircuitInputs {
  validateAction(args.action);
  if (args.strategyParams.length !== 8) {
    throw new Error("strategyParams must be exactly 8 field elements");
  }
  const amount = args.action.type === "EXTRACT" ? (args.action.amount ?? 0) : 0;
  return {
    commitment: toField(args.commitment).toString(),
    matchId: toField(BigInt("0x" + args.matchId.replace(/-/g, ""))).toString(),
    turnNumber: String(args.turn),
    selfBalance: String(args.selfBalance),
    opponentBalance: String(args.opponentBalance),
    action: actionCode(args.action).toString(),
    amount: String(amount),
    circuitVersion: String(args.circuitVersion),
    salt: toField(args.salt).toString(),
    strategyParams: args.strategyParams.map((p) => toField(p).toString()),
  };
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
  proveMs: number;
}

function timeoutError(ms: number): Error {
  return new Error(`proof generation timed out after ${ms}ms`);
}

/**
 * Path of the prove child script. It lives at <project>/scripts/, one
 * level up from this file whether this file is src/circuit.ts (tsx) or
 * dist/circuit.js (built).
 */
function proveChildPath(): string {
  return fileURLToPath(new URL("../scripts/prove-child.mjs", import.meta.url));
}

/**
 * Generate a Groth16 proof locally with snarkjs, in a CHILD PROCESS,
 * bounded by timeoutMs. The child is SIGKILLed on timeout, so a stalled
 * prove cannot block the server's event loop or the response deadline —
 * the caller fails closed (HOLD, no proof).
 *
 * WHY A CHILD PROCESS — see scripts/prove-child.mjs. In short: snarkjs
 * proving is synchronous CPU work (a JS setTimeout cannot interrupt it on
 * the main thread), and a worker thread is incompatible with snarkjs's
 * ffjavascript/web-worker dependency ("Worker is not a constructor",
 * verified 2026-11-15). A child process is a full Node instance where
 * proving works, and it can be killed.
 *
 * Measured 2026-11-15 on the dev VM: the known-passing prove takes ~2 s
 * of CPU; under heavy CPU contention from a concurrent process the same
 * prove took much longer in wall time, so the timeout must be real (it
 * is, here — SIGKILL) rather than a JS race.
 */
export async function generateProof(
  inputs: CircuitInputs,
  timeoutMs: number,
): Promise<ProofResult> {
  const started = Date.now();
  const child: ChildProcessWithoutNullStreams = spawn(
    process.execPath,
    [proveChildPath()],
    { stdio: ["pipe", "pipe", "pipe"] },
  );

  const payload = JSON.stringify({
    inputs: inputs as unknown as Record<string, string | string[]>,
    wasmPath: resolve(process.cwd(), config.wasmPath),
    zkeyPath: resolve(process.cwd(), config.zkeyPath),
  });

  return new Promise<ProofResult>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      done(() => reject(timeoutError(timeoutMs)));
    }, timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => {
      stdout += d;
    });
    child.stderr.on("data", (d: string) => {
      stderr += d;
    });
    child.on("error", (err) => {
      done(() => reject(err));
    });
    child.on("close", (code) => {
      done(() => {
        let result: Record<string, unknown> | null = null;
        try {
          result = JSON.parse(stdout.trim()) as Record<string, unknown>;
        } catch {
          result = null;
        }
        if (result && result.ok === true) {
          resolve({
            proof: result.proof,
            publicSignals: result.publicSignals as string[],
            proveMs: Date.now() - started,
          });
        } else if (result && typeof result.error === "string") {
          reject(new Error(result.error));
        } else {
          reject(
            new Error(
              `prove child exited with code ${code} and no valid result` +
                (stderr ? `: ${stderr.slice(0, 200)}` : ""),
            ),
          );
        }
      });
    });

    child.stdin.on("error", () => {
      // Child already gone — the close handler reports it.
    });
    child.stdin.write(payload);
    child.stdin.end();
  });
}

let cachedVkey: unknown | null = null;

/** Verify a proof locally against the exported verification key. */
export async function verifyProofLocally(
  proof: unknown,
  publicSignals: string[],
): Promise<boolean> {
  if (!cachedVkey) {
    cachedVkey = JSON.parse(readFileSync(config.vkeyPath, "utf8"));
  }
  return snarkjs.groth16.verify(cachedVkey as never, publicSignals, proof as never);
}
