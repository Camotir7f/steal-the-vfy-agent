# Railway deploy checklist for the Steal the VFY agent.
# The service is a plain Node.js app: Railway auto-detects it (Nixpacks),
# runs `npm install && npm run build`, then `npm start`.
# It listens on $PORT (Railway sets this automatically) and serves /health.

## 0. Before you deploy — fill in your strategy first
#    - Edit src/policy.ts: set STRATEGY_PARAMS to YOUR 8 values
#      (currently the all-zeros placeholder = HOLD every turn).
#    - Recompute the commitment and register it on the Agent Games
#      dashboard BEFORE the next pairing (the platform freezes the
#      commitment when matches are paired):
#        npm run build
#        STRATEGY_SALT=<your salt> STRATEGY_PARAMS='[1,0,0,0,0,0,0,0]' npm run commitment
#      Paste the printed 0x hash into Dashboard -> My Agents -> Edit agent
#      -> Steal the VFY section.
#    - NOTE: the Steal the VFY tournament (13-17 Nov 2026) appears to have
#      already locked (see README.md). Confirm on the dashboard that a new
#      registration is still accepted before deploying for this season.

## 1. Push this folder to GitHub (new repo, e.g. steal-the-vfy-agent)
#    - Public repo is fine (no secrets in the code; .env is gitignored).
#    - Make sure circuits/*.wasm + *.zkey are committed (they are needed
#      at runtime).
#    - NEVER commit .env, data/seen.json, or your salt/params anywhere
#      except src/policy.ts (params) and Railway Variables (salt).

## 2. Railway dashboard (railway.app, sign in with GitHub)
#    - New Project -> Deploy from GitHub repo -> pick steal-the-vfy-agent.
#    - If the repo list shows "No repositories found", use
#      "Configure GitHub App" and grant the app access to the repo
#      (this step was needed for the Proof Gatekeeper project).
#    - Variables (set these in the Railway dashboard, NOT in the repo):
#        AGENT_GAMES_HMAC_SECRET = <from Agent Games dashboard, Rotate Secret>
#        KURIER_API_KEY          = <from testnet.kurier.xyz / kurier.xyz>
#        STRATEGY_SALT           = <your private salt, decimal or 0x-hex>
#        KURIER_NETWORK          = testnet        (start here; mainnet later)
#        AGENT_PATH              = /agent
#        REGISTERED_VK_HASH      = 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
#        RESPONSE_DEADLINE_MS    = 240000
#        PROOF_TIMEOUT_MS        = 120000
#      (PORT is set automatically by Railway — do not set it yourself.)
#    - To get the service running before the real secrets exist, you may
#      set AGENT_GAMES_HMAC_SECRET and KURIER_API_KEY to the placeholder
#      "sementara-dulu" (as was done for the Gatekeeper), then replace them
#      with the real values and redeploy. The placeholder secret makes
#      preflight FAIL — it is only for getting a URL + /health out.
#    - Optional: add a Volume mounted at /data, then set
#        SEEN_DB_PATH = /data/seen.json
#      so the turn-idempotency seen-set survives restarts/redeploys. Without
#      a volume the seen-set resets on restart (the platform also tracks
#      idempotency, so this is defence-in-depth, not a single point of
#      failure).

## 3. Get the public URL
#    - Settings -> Domains -> Generate Domain.
#    - You get https://<name>.up.railway.app — that is the endpoint.
#    - Check https://<name>.up.railway.app/health returns {"ok":true,...}.

## 4. Register on the Agent Games dashboard
#    - Paste the Railway URL + the agent path, e.g.
#      https://<name>.up.railway.app/agent
#    - Rotate Secret -> copy the one-time plaintext -> set it as
#      AGENT_GAMES_HMAC_SECRET in Railway -> redeploy.
#    - Run preflight from the dashboard. It must pass before the platform
#      marks the agent active.
#    - Start with unscored practice turns, then enter scored rounds.
