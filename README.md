# Steal the VFY agent — zkVerify Agent Games

A public HTTPS endpoint that answers signed turn envelopes with a
deterministic policy action and a Groth16 proof that the action follows the
pre-committed strategy. Built in TypeScript (Node.js ≥ 22), built-in `http`,
no framework.

## ⚠️ Tournament status — read first

**The Steal the VFY tournament (schedule 13–17 Nov 2026) appears to have
already locked.** The event page says "entries lock once the tournament is
paired", Swiss rounds started 13 Nov, and two independent participants
reported on 15 Nov that the track was already closed while its Swiss
tournament was in progress. **If you have not already registered a Steal
the VFY agent, you most likely cannot enter this season.** This agent is
still complete and tested — use it for practice turns, for the next season,
or as the base for a future entry — but do not assume a new registration
will be accepted. Check the dashboard first:
Dashboard → My Agents → Steal the VFY.

## How it works

1. The platform POSTs a signed turn envelope to `/agent` (HMAC-SHA256 over
   the RAW body, header `x-agent-games-signature`).
2. The server verifies the HMAC **before** parsing, validates the envelope,
   and checks that `strategyCommitment.hash` matches the commitment computed
   from your own `STRATEGY_PARAMS` + `STRATEGY_SALT`. A mismatch fails
   closed to HOLD.
3. `policy(state, STRATEGY_PARAMS)` returns the deterministic action.
4. The server builds the 17 circuit inputs, computes the `publicInputsHash`
   audit field, generates a Groth16 proof locally with snarkjs, and verifies
   it locally before responding.
5. The signed response echoes `matchId` + `turn`, carries the action, and
   nests the raw proof + `public_signals` **inside** `policyProof`.
6. Kurier submission to zkVerify is OPTIONAL and never blocks the response:
   the server races finalization against a short grace window and attaches
   `proofReference` only if it finalizes in time.

On ANY error or timeout the server returns a signed HOLD with NO proof and
NO amount field. It never crashes into an invalid submission.

## The game (from the official spec)

- Both agents start at 100 VFY. 20 turns per match, highest balance wins.
- Actions: **HOLD** (0 VFY), **FORTIFY** (cost 2, blocks up to 6 incoming
  extraction), **EXTRACT N** (steal up to N ≤ 10; a fortified opponent cuts
  the gain by 6). Both agents act simultaneously each turn.
- Swiss, 7 rounds → Top 16 knockout. Score: win +18, draw +9, loss +3,
  reliability bonus +0..+2, timeout −1/turn, invalid proof −2/turn.
- Turn deadline 5 minutes; the platform waits ~30 s per push.

## File structure

```
steal-vfy/
  README.md            this file
  RAILWAY.md           deploy checklist (Railway)
  package.json         deps: snarkjs, circomlibjs, viem
  tsconfig.json        strict TS, NodeNext
  railway.json         Nixpacks build + /health check
  .env.example         every variable, with comments (copy to .env)
  .gitignore           .env, data/, node_modules/, dist/
  circuits/
    vfy-policy.wasm        official circuit (SHA-256 bc099825…134d2)
    vfy-policy_final.zkey  official proving key (SHA-256 f9666a16…6ce41)
    verification_key.json  exported with snarkjs (Groth16/BN128, nPublic 9)
  src/
    index.ts       entrypoint (listens on PORT)
    server.ts      HTTP server: raw-body HMAC, /health, /agent, preflight,
                   turn handling, hard deadline, fail-closed HOLD
    policy.ts      STRATEGY_PARAMS (TODO — YOURS) + pure policy() + validation
    hash.ts        publicInputsHash, verbatim the /build formula
    commitment.ts  Poseidon(params[0..7], salt) commitment
    circuit.ts     field encoding, input builder, prove via child process
    kurier.ts      optional Kurier submit + Finalized polling
    hmac.ts        HMAC sign/verify (timing-safe)
    config.ts      env only (never hardcode secrets)
    seen.ts        persistent (matchId,turn) idempotency set
    snarkjs.d.ts / circomlibjs.d.ts   minimal type declarations
  scripts/
    commitment.mjs   print ONLY the commitment hash (for dashboard registration)
    prove-child.mjs  runs snarkjs fullProve in a child process (see below)
    harness.ts       local test harness (see below)
  data/
    seen.json      runtime state (gitignored)
```

## Circuit facts (verified against the official artifacts, 2026-11-15)

- Groth16 / BN128, Circom 2.x. vkHash
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  (from `https://agentgames.zkverify.io/api/circuit-info`).
- **17 inputs, 9 public signals.** Input names (verified: each accepted by
  `snarkjs wtns.calculate`, wrong names rejected):
  `commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
  amount, circuitVersion, salt` (9 singles) + `strategyParams` (array of
  exactly 8 field elements). The input is `turnNumber` (not `turn`);
  `main.*` prefixes do NOT work; `publicInputsHash` is NOT a circuit input.
- **Commitment = Poseidon(strategyParams[0], …, strategyParams[7], salt)**
  — params first, salt last, 9 Poseidon inputs. Verified:
  `Poseidon([1,0,0,0,0,0,0,0,99]) =
  13055895323729736618583278851078047761755013433841345493233879763754052669212`,
  exactly `publicSignals[1]` of a passing witness for the same inputs.
  `Poseidon(salt, params)`, `Poseidon(params)` without salt, and nested
  variants all fail the circuit's commitment assert (line 72).
- **Public signals, in snarkjs order:**
  `[w1, commitment, matchId, turnNumber, selfBalance, opponentBalance,
  action, amount, circuitVersion]`.
  `w[0]` is a circuit OUTPUT whose exact formula is **undetermined** — it is
  NOT the keccak `publicInputsHash` and NOT a simple Poseidon of the fields
  (12 combinations tested, none matched). The harness passes `public_signals`
  through EXACTLY as snarkjs returns them; it does not need to interpret
  `w[0]`. `w[1]` IS the commitment (verified).
- **Action encoding:** HOLD=0, FORTIFY=1, EXTRACT=2. `circuitVersion` input
  = 1 for `"v1"`. `matchId` = `BigInt("0x" + uuid without hyphens)` — the
  same encoding as the `publicInputsHash` computation.
- **Policy semantics, PARTIALLY reversed (read `src/policy.ts`):**
  `params[0]` IS the EXTRACT amount — params `[N,0,0,0,0,0,0,0]` accept
  EXTRACT N (verified N=1,2,5,10) and REFUSE HOLD/FORTIFY (witness assert,
  line 140). The roles of `params[1..7]` are NOT documented on the official
  site and were NOT fully reverse-engineered (asserts at lines 75, 76, 90,
  140, 149, …). Do NOT invent meanings for them. Until their semantics are
  determined — from the platform's circuit documentation, the dashboard's
  commitment form, or your own circuit probing — the policy cannot express
  a HOLD/FORTIFY strategy through `params[1..7]`; `policy()` returns HOLD
  as the fail-closed default when `params[0]` is 0.
- **Proof timing (measured 2026-11-15 on the dev VM):** the
  known-passing prove takes **~1.9 s** of CPU when the machine is free and
  **~3.2–3.6 s wall** under heavy CPU contention from a concurrent process
  (harness runs 3–4). The turn window is 5 min (platform waits ~30 s per
  push), so a few seconds of proving leaves ample margin.
- **Proofs run in a CHILD PROCESS (`scripts/prove-child.mjs`), not the
  main thread and not a worker thread.** Two real failures drove this:
  (a) snarkjs proving is synchronous CPU work — a JS `setTimeout` cannot
  interrupt a stalled prove on the main thread (an early attempt ran 8+
  minutes with no output and had to be killed); (b) a worker thread does
  NOT work — snarkjs depends on ffjavascript, which depends on the
  `web-worker` package, and that polyfill breaks inside a worker thread
  ("Worker is not a constructor", verified 2026-11-15). A child process
  is a full Node instance where proving works, and the parent SIGKILLs it
  on `PROOF_TIMEOUT_MS` (default 120 s), so the timeout is real and the
  server's event loop stays responsive. One more quirk: ffjavascript
  leaves worker threads alive, so a child that finished its proof in ~2 s
  CPU still had not exited after 180 s wall — the child therefore calls
  `process.exit()` explicitly after writing its result.
- **The TODO placeholder params do NOT produce a provable HOLD.** With
  params all zeros the circuit REFUSES the HOLD action (witness assert),
  so the server returns HOLD with NO proof attached — the fail-closed
  path, verified by the harness. That means the placeholder is a
  do-nothing agent until you fill in real params AND verify the circuit
  accepts the resulting actions in the harness. Do not register a
  commitment for a HOLD/FORTIFY strategy until that check passes.
- **Idempotency keys are deterministic:** `idempotencyKey` is the
  UUID-formatted SHA-256 of `"matchId:turn"`, so a retried push returns
  the SAME key and the platform dedupes it. Every answered turn
  (including fail-closed HOLDs) is recorded in `data/seen.json`, so a
  retry is answered HOLD again instead of generating a second proof.

## Your strategy — TODO (yours, not the model's)

`STRATEGY_PARAMS` in `src/policy.ts` is a clearly-marked TODO constant
(currently all zeros = HOLD every turn, the fail-closed placeholder). It is
an array of EXACTLY 8 field elements. Fill it in with YOUR values — the
model must not invent, suggest, or hardcode a strategy for you.

After changing the params you MUST recompute the commitment and re-register
it BEFORE the next pairing (the platform freezes the commitment when
matches are paired):

```sh
npm run build
STRATEGY_SALT=<your salt> STRATEGY_PARAMS='[1,0,0,0,0,0,0,0]' npm run commitment
# prints ONLY the 0x hash — paste it into the dashboard
# (Dashboard -> My Agents -> Edit agent -> Steal the VFY section)
```

The salt comes from `STRATEGY_SALT` (env only). Never print, log, or commit
the salt or the params. The commitment hash itself is public (it goes on
the dashboard); the salt + params must stay secret until you choose to
reveal them.

## Setup

```sh
npm install
npm run build
cp .env.example .env   # fill in the real values (see .env.example)
npm start              # listens on :3000, GET /health
```

Required env: `AGENT_GAMES_HMAC_SECRET` (dashboard → Rotate Secret, shown
once), `STRATEGY_SALT`. `KURIER_API_KEY` is optional (testnet.kurier.xyz /
kurier.xyz) — without it the agent still answers every turn; it just omits
the optional `proofReference`.

## Test harness

```sh
npm run build && npm run harness
```

Checks (all must pass): HMAC sign/verify, policy determinism, the verified
EXTRACT behaviour, `publicInputsHash` against a hand-rolled implementation
of the `/build` formula, the commitment formula against the verified value,
a full Groth16 prove + local verify for the known-passing case
(params `[1,0,0,0,0,0,0,0]`, salt 99, EXTRACT 1 — including a check that
the circuit REFUSES HOLD for those params), and a live-server round-trip
(preflight, valid turn, duplicate turn — which must return the SAME
deterministic idempotencyKey — commitment mismatch, stale turn, unsigned
turn → 401). The harness uses TEST secrets only and never contacts the
platform or Kurier with a real key. Last run (2026-11-15): **35 passed,
0 failed**, known-passing prove 3,228 ms under CPU contention.

## Register + deploy

See `RAILWAY.md`. In short: push to GitHub → Railway project from the repo
→ set Variables (`AGENT_GAMES_HMAC_SECRET` from Rotate Secret,
`KURIER_API_KEY` from testnet.kurier.xyz, `STRATEGY_SALT`, `KURIER_NETWORK`
= testnet) → Generate Domain → register the endpoint on the dashboard
(`https://<name>.up.railway.app/agent`) → run preflight → practice turns.

## Open items (honest list)

1. **Track lock** — see the warning at the top. Confirm on the dashboard
   whether a new Steal the VFY registration is still accepted.
2. **params[1..7] semantics** — unknown (see "Circuit facts"). Do not
   register a commitment for a HOLD/FORTIFY strategy until you have verified
   the circuit accepts HOLD/FORTIFY for your params in the local harness.
   (With the all-zero placeholder the circuit refuses HOLD outright, so
   there is currently NO provable HOLD/FORTIFY action at all.)
3. **Preflight format** — assumed from the Proof Gatekeeper standard
   (`agent-games.preflight.v1` → `{ ok: true, protocolVersion: "v1" }`);
   the Steal the VFY `/build` page does not publish a distinct preflight
   shape. If the dashboard preflight fails, check the exact expected shape
   there.
4. **w[0] public signal** — formula undetermined (see "Circuit facts"). It
   does not block anything: the harness passes `public_signals` through
   verbatim.
5. **Prove-time outlier** — one 8+ minute prove attempt (see "Proof
   timing"). Mitigated by the child-process design + `PROOF_TIMEOUT_MS`
   (SIGKILL) + fail-closed HOLD. Re-measure on Railway (dedicated CPU)
   after deploy; if prove is ever slow there, lower `PROOF_TIMEOUT_MS`
   rather than risking the ~30 s push window.

## Security

- Secrets live in env vars only (`.env` is gitignored). Never paste a
  private key, wallet seed, strategy salt, or API key into a chat.
- The server never logs the salt, the params, or full proofs.
- Fail closed everywhere: bad HMAC → 401; bad envelope, commitment
  mismatch, duplicate turn, proof failure, timeout → signed HOLD, no proof.
- Start on testnet (`KURIER_NETWORK=testnet`).
