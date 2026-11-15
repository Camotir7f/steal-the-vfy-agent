// Strategy commitment: Poseidon(params[0], ..., params[7], salt).
// Params first, salt LAST — 9 Poseidon inputs, via circomlibjs.
//
// VERIFIED 2026-11-15 against the official vfy-policy artifacts:
//   Poseidon([1,0,0,0,0,0,0,0,99]) =
//   13055895323729736618583278851078047761755013433841345493233879763754052669212
// which is EXACTLY publicSignals[1] of a passing witness for those same
// inputs. Poseidon(salt, params), Poseidon(params) without the salt, and
// nested variants all FAIL the circuit's commitment assert (line 72).
//
// The commitment is what you register on the dashboard (Dashboard -> My
// Agents -> Edit agent, Steal the VFY section) BEFORE Swiss Round 1. The
// platform freezes it when matches are paired and sends it back in every
// turn envelope as strategyCommitment.hash. The server refuses to answer
// a turn whose envelope commitment does not match this local value.
//
// NEVER log or print the salt or the params — only the resulting hash.
// The commitment hash itself is public (it goes on the dashboard); the
// salt + params must stay secret until you choose to reveal them.
import { buildPoseidon } from "circomlibjs";
import { FIELD_PRIME, toField } from "./circuit.js";

export const PARAM_COUNT = 8;

/** Validate the 8 strategy params (field elements, non-negative). */
export function validateParams(params: readonly bigint[]): void {
  if (!Array.isArray(params) || params.length !== PARAM_COUNT) {
    throw new Error(`STRATEGY_PARAMS must be exactly ${PARAM_COUNT} field elements`);
  }
  for (const p of params) {
    if (typeof p !== "bigint" || p < 0n || p >= FIELD_PRIME) {
      throw new Error("STRATEGY_PARAMS must be field elements (0 <= p < BN128 prime)");
    }
  }
}

let cachedPoseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

async function getPoseidon() {
  if (!cachedPoseidon) cachedPoseidon = await buildPoseidon();
  return cachedPoseidon;
}

/**
 * Compute the commitment as a field element (decimal bigint).
 * Poseidon(params[0], ..., params[7], salt).
 */
export async function computeCommitment(
  params: readonly bigint[],
  salt: bigint,
): Promise<bigint> {
  validateParams(params);
  const poseidon = await getPoseidon();
  const inputs = [...params.map((p) => toField(p)), toField(salt)];
  const out = poseidon(inputs);
  return toField(BigInt(poseidon.F.toString(out)));
}

/** The same commitment as a 0x-prefixed 32-byte hex string (dashboard form). */
export async function computeCommitmentHex(
  params: readonly bigint[],
  salt: bigint,
): Promise<string> {
  const v = await computeCommitment(params, salt);
  return "0x" + v.toString(16).padStart(64, "0");
}
