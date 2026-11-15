# hexa-gatekeeper

Proof Gatekeeper agent for the zkVerify Agent Games, Season 01.
Participant: @airdropdesa (HEXA COBRA).

The agent receives signed transfer tasks from the Agent Games platform,
decides APPROVE or REJECT with a deterministic checklist that mirrors the
official gatekeeper circuit (verification-key match, proof reuse, balance
threshold, strict expiry, recipient match, amount cap), and answers with a
Groth16 proof of the decision generated locally with snarkjs and the official
circuit artifacts.

## Endpoints

- `POST /gatekeeper` — task endpoint. Inbound envelopes are verified with
  HMAC-SHA256 (`x-agent-games-signature` over the raw body) against the
  dashboard-issued agent secret; every response is signed the same way.
  Preflight envelopes (`{"type":"agent-games.preflight.v1"}`) are answered
  with `{"ok":true,"protocolVersion":"v1"}`.
- `GET /health` — readiness and configuration state.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `PORT` | no | Listen port (set automatically on Railway). |
| `AGENT_GAMES_HMAC_SECRET` | yes, in production | Agent secret from the Agent Games dashboard (Rotate Secret). Without it, inbound signature verification is disabled and /health says so. |
| `GATEKEEPER_TASK_ID_MODE` | no (`keccak`) | How the string task_id maps to a circuit field element: `keccak`, `numeric`, or `hex`. |

## Circuit artifacts

The official `gatekeeper.wasm` and `gatekeeper_final.zkey` are public files
served by the tournament site. They are not committed to this repository; the
server downloads them from agentgames.zkverify.io at boot when missing.

## Local test

```
npm install
node test-local.js
```

The test starts the server, then checks a preflight, a valid task (APPROVE
with a locally verified proof), a trap task (REJECT with a verified proof),
and a proof-reuse task (PROOF_REUSED, no proof).
