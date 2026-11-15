// Compute the strategy commitment hash for registration on the dashboard.
//
//   STRATEGY_SALT=<salt> STRATEGY_PARAMS='[1,0,0,0,0,0,0,0]' npm run commitment
//
// Prints ONLY the commitment hash (0x + 64 hex chars) to stdout — never the
// salt or the params. Copy the printed hash into the dashboard:
// Dashboard -> My Agents -> Edit agent -> Steal the VFY section.
//
// commitment = Poseidon(params[0], ..., params[7], salt), params first,
// salt LAST (verified against the official vfy-policy circuit, 2026-11-15).
//
// IMPORTANT: the commitment you register MUST be computed from the SAME
// params that are in src/policy.ts (STRATEGY_PARAMS) — the server proves
// turns with those params, and the platform rejects any turn whose envelope
// commitment hash does not match the registered one. So: fill in
// STRATEGY_PARAMS in src/policy.ts first, then pass the SAME 8 values here
// via the STRATEGY_PARAMS env var (JSON array), with the SAME salt as
// STRATEGY_SALT in your .env / Railway variables.
//
// This script is intentionally standalone (no build step, no import of the
// server code) so it only ever needs the two env vars below. It never
// writes anything to disk.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs");

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toField(v) {
  const r = v % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

function parseField(s) {
  const t = String(s).trim();
  return toField(t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t));
}

function fail(msg) {
  console.error(`commitment: ${msg}`);
  process.exit(1);
}

const saltRaw = process.env.STRATEGY_SALT;
if (!saltRaw || saltRaw.trim() === "") {
  fail(
    "STRATEGY_SALT is not set. Set it to your private salt (decimal or 0x-hex), e.g.:\n" +
      "  STRATEGY_SALT=0x... npm run commitment\n" +
      "The salt must be the SAME value as STRATEGY_SALT in your .env / Railway variables.",
  );
}

const paramsRaw = process.env.STRATEGY_PARAMS;
if (!paramsRaw || paramsRaw.trim() === "") {
  fail(
    "STRATEGY_PARAMS is not set. Set it to the SAME 8 values as STRATEGY_PARAMS in src/policy.ts,\n" +
      "as a JSON array, e.g.:\n" +
      "  STRATEGY_PARAMS='[1,0,0,0,0,0,0,0]' npm run commitment",
  );
}

let params;
try {
  params = JSON.parse(paramsRaw);
} catch {
  fail("STRATEGY_PARAMS is not valid JSON. Expected e.g. '[1,0,0,0,0,0,0,0]'.");
}
if (!Array.isArray(params) || params.length !== 8) {
  fail("STRATEGY_PARAMS must be a JSON array of exactly 8 field elements.");
}
let salt;
try {
  salt = parseField(saltRaw);
  params = params.map((p) => parseField(p));
} catch {
  fail("STRATEGY_SALT / STRATEGY_PARAMS must be decimal or 0x-hex field elements.");
}

const poseidon = await buildPoseidon();
const out = poseidon([...params, salt]);
const commitment = toField(BigInt(poseidon.F.toString(out)));
// ONLY the hash is printed. Never the salt, never the params.
console.log("0x" + commitment.toString(16).padStart(64, "0"));
