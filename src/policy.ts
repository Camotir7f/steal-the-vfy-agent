// The policy: a pure, deterministic function from game state to action.
// The circuit proves that the returned action is the output of THIS policy
// for the committed strategy params — so policy() and the circuit must
// agree exactly. If they disagree, the witness refuses and the server
// fails closed to HOLD with no proof.
//
// ============================================================================
// TODO — THE STRATEGY IS YOURS. FILL IN STRATEGY_PARAMS.
// ============================================================================
// STRATEGY_PARAMS is an array of EXACTLY 8 field elements (non-negative
// integers < the BN128 field prime). The commitment you register on the
// dashboard is Poseidon(params[0], ..., params[7], salt) — see
// src/commitment.ts and `npm run commitment`. After changing the params you
// MUST recompute the commitment and re-register it BEFORE the next pairing;
// the platform freezes the commitment when matches are paired and rejects
// any turn whose envelope commitment hash does not match it.
//
// DO NOT invent, suggest, or hardcode a "good" strategy here. The values
// below are the PLACEHOLDER (all zeros) — they are not a strategy. With
// the placeholder the policy returns HOLD every turn (fail-closed default).
// ============================================================================

export const STRATEGY_PARAMS: readonly bigint[] = [
  0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n,
] as const;

/** Action codes — identical in the circuit and in the publicInputsHash. */
export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 } as const;

export type ActionType = "HOLD" | "FORTIFY" | "EXTRACT";

export interface Action {
  type: ActionType;
  /** EXTRACT amount only. MUST be omitted entirely for HOLD / FORTIFY. */
  amount?: number;
}

export interface GameState {
  selfBalance: number;
  opponentBalance: number;
  /** Turn until which self is fortified, or null. */
  selfFortifiedUntilTurn: number | null;
  /** Turn until which the opponent is fortified, or null. */
  opponentFortifiedUntilTurn: number | null;
  turn: number;
}

export const MAX_EXTRACT = 10;
export const FORTIFY_COST = 2;
export const FORTIFY_BLOCK = 6;

/**
 * VERIFIED circuit behaviour (probed against the official vfy-policy
 * artifacts, 2026-11-15):
 *
 * - strategyParams[0] IS the EXTRACT amount. With params = [N, 0, 0, 0, 0,
 *   0, 0, 0] the circuit ACCEPTS action EXTRACT with amount N (verified
 *   N = 1, 2, 5, 10) and REFUSES HOLD and FORTIFY for the same params
 *   (witness assert, circuit line 140). So when params[0] > 0 the policy
 *   MUST return EXTRACT params[0] — anything else cannot be proven.
 * - The circuit enforces amount bounds (asserts at lines 75, 76, 90, 149,
 *   ...). The platform caps EXTRACT at 10, so the policy clamps the amount
 *   to min(params[0], 10, opponentBalance).
 *
 * OPEN — NOT VERIFIED (do not guess):
 * The roles of params[1..7] are NOT documented on the official site and
 * were NOT fully reverse-engineered. They presumably select HOLD vs
 * FORTIFY (and possibly modulate the extract amount) for states where the
 * strategy does not extract — but their exact semantics (thresholds,
 * comparisons, which param controls what) are UNKNOWN. Until those
 * semantics are determined — from the platform's circuit documentation,
 * the dashboard's commitment form, or your own circuit probing — this
 * function CANNOT express a HOLD/FORTIFY strategy through params[1..7].
 * What it does instead: when params[0] is 0 (or the extractable amount
 * is 0) it returns HOLD, and the server attempts the proof; if the
 * circuit refuses HOLD for your params, the turn fails closed to HOLD
 * with NO proof (the platform scores that as HOLD, −2 for the invalid
 * proof — the same as submitting nothing). DO NOT register a commitment
 * for a HOLD/FORTIFY strategy until you have verified the circuit accepts
 * HOLD/FORTIFY for your params in the local harness.
 */
export function policy(state: GameState, params: readonly bigint[]): Action {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error("STRATEGY_PARAMS must be exactly 8 field elements");
  }
  for (const p of params) {
    if (p < 0n) throw new Error("STRATEGY_PARAMS must be non-negative");
  }

  const extractParam = params[0];

  // Verified path: params[0] > 0 -> the circuit only accepts EXTRACT N.
  if (extractParam > 0n) {
    const wanted = Number(extractParam);
    const amount = Math.min(wanted, MAX_EXTRACT, Math.max(0, state.opponentBalance));
    if (amount >= 1) {
      return { type: "EXTRACT", amount };
    }
    // Opponent has nothing left to take. Fall through to HOLD below.
    // OPEN: whether the circuit accepts HOLD when params[0] > 0 is
    // unverified — the server will fail closed if the witness refuses.
  }

  // params[0] == 0 (or nothing extractable): HOLD.
  // OPEN: the HOLD/FORTIFY selection logic for params[1..7] is unknown —
  // see the comment above. This branch is the fail-closed default, not a
  // strategy. Fill in your own selection logic here ONLY once you know
  // how params[1..7] map to the circuit's HOLD/FORTIFY checks.
  return { type: "HOLD" };
}

/** Validate an action for the response schema. Throws on violations. */
export function validateAction(action: Action): void {
  if (action.type === "EXTRACT") {
    if (typeof action.amount !== "number" || !Number.isInteger(action.amount)) {
      throw new Error("EXTRACT requires an integer amount");
    }
    if (action.amount < 1 || action.amount > MAX_EXTRACT) {
      throw new Error(`EXTRACT amount must be 1..${MAX_EXTRACT}`);
    }
  } else {
    // HOLD / FORTIFY must carry NO amount field at all (the schema rejects
    // the field even when it is 0).
    if ("amount" in action && action.amount !== undefined) {
      throw new Error(`${action.type} must not carry an amount`);
    }
  }
}

/** Encode an action for the circuit / publicInputsHash (HOLD=0, FORTIFY=1, EXTRACT=2). */
export function actionCode(action: Action): bigint {
  return BigInt(ACTION_CODE[action.type]);
}
