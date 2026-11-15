// publicInputsHash — the OPTIONAL audit field on policyProof.
// Verbatim the formula from https://agentgames.zkverify.io/build:
// keccak256 of ABI-packed fields, each padded to 32 bytes big-endian.
// Field order (EXACT — the platform computes the same hash independently
// and rejects any proof where the hashes diverge):
//   1. strategyCommitment.hash
//   2. matchId as BigInt("0x" + uuid without hyphens)
//   3. turn
//   4. selfBalance
//   5. opponentBalance
//   6. action code (HOLD=0, FORTIFY=1, EXTRACT=2)
//   7. amount (0 for HOLD / FORTIFY)
//   8. circuitVersion ("v1" -> 1)
//
// This hash is a sanity check only. The platform verifies the actual
// Groth16 proof + public_signals, so a correct hash alone does NOT pass
// a turn.
import { concat, keccak256, numberToHex } from "viem";
import { actionCode, type Action } from "./policy.js";

export function computePublicInputsHash(args: {
  commitment: string; // "0x..." hex (32 bytes)
  matchId: string; // UUID with hyphens
  turn: number;
  selfBalance: number;
  opponentBalance: number;
  action: Action;
  circuitVersion: number; // "v1" -> 1
}): string {
  const amount = args.action.type === "EXTRACT" ? (args.action.amount ?? 0) : 0;
  return keccak256(
    concat([
      numberToHex(BigInt(args.commitment), { size: 32 }),
      numberToHex(BigInt("0x" + args.matchId.replace(/-/g, "")), { size: 32 }),
      numberToHex(BigInt(args.turn), { size: 32 }),
      numberToHex(BigInt(args.selfBalance), { size: 32 }),
      numberToHex(BigInt(args.opponentBalance), { size: 32 }),
      numberToHex(actionCode(args.action), { size: 32 }),
      numberToHex(BigInt(amount), { size: 32 }),
      numberToHex(BigInt(args.circuitVersion), { size: 32 }),
    ]),
  );
}
