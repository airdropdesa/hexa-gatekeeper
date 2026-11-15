// HEXA Gatekeeper: Proof Gatekeeper agent for zkVerify Agent Games Season 01.
// Participant: @airdropdesa. One job: receive a signed transfer task, decide
// APPROVE or REJECT by the tournament's deterministic checklist, and answer
// with a Groth16 proof of that decision generated with the official circuit.
//
// Protocol (from the official builder guide and circuit behaviour):
//   POST /gatekeeper  header x-agent-games-signature = HMAC-SHA256 hex of the
//                     raw body, keyed with the dashboard-issued agent secret.
//   Envelope fields:  task_id, registered_vk, proof_vk, minimum,
//                     public_balance, expiry_block, current_block, recipient,
//                     condition_recipient, amount, max_transfer, proof_tx.
//   Preflight:        {"type":"agent-games.preflight.v1"} is answered with
//                     {"ok":true,"protocolVersion":"v1"}.
//   Response:         {decision, reason_code, proof_tx, proof, public_signals}
//                     signed the same way. PROOF_REUSED answers carry no proof.
//   GET /health       readiness probe.

const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak256 } = require('js-sha3');

const PORT = process.env.PORT || 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');

// ---------- HMAC ----------
function hmacHex(secret, raw) {
  return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}
function verifyInbound(secret, raw, header) {
  if (!secret) return true; // local testing only; health reports this state
  if (!header) return false;
  const given = String(header).replace(/^sha256=/, '');
  const expected = hmacHex(secret, raw);
  const a = Buffer.from(expected);
  const b = Buffer.from(given);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function signOutbound(secret, raw) {
  return secret ? hmacHex(secret, raw) : '';
}

// ---------- Decision checklist (mirrors the circuit exactly) ----------
const seenProofTx = new Map(); // proof_tx (lowercase) -> task_id
function decide(t) {
  const registeredVk = String(t.registered_vk || '').toLowerCase();
  const proofVk = String(t.proof_vk || '').toLowerCase();
  if (proofVk !== registeredVk) return { decision: 'REJECT', reason: 'VK_SUBSTITUTION' };

  const proofTx = String(t.proof_tx || '').toLowerCase();
  if (proofTx) {
    const prev = seenProofTx.get(proofTx);
    if (prev !== undefined && prev !== String(t.task_id)) {
      return { decision: 'REJECT', reason: 'PROOF_REUSED' };
    }
    if (prev === undefined) seenProofTx.set(proofTx, String(t.task_id));
  }

  if (BigInt(t.public_balance) < BigInt(t.minimum)) {
    return { decision: 'REJECT', reason: 'THRESHOLD_MISMATCH' };
  }
  if (BigInt(t.current_block) >= BigInt(t.expiry_block)) {
    return { decision: 'REJECT', reason: 'EXPIRED_CONDITION' };
  }
  if (String(t.recipient || '').toLowerCase() !== String(t.condition_recipient || '').toLowerCase()) {
    return { decision: 'REJECT', reason: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(t.amount) > BigInt(t.max_transfer)) {
    return { decision: 'REJECT', reason: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason: 'VALID_CONDITION' };
}

// ---------- Proof generation ----------
function taskIdToField(taskId) {
  const id = String(taskId || '');
  if (TASK_ID_MODE === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? (BigInt(digits) % FIELD_PRIME).toString() : '0';
  }
  if (TASK_ID_MODE === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? (BigInt('0x' + hex) % FIELD_PRIME).toString() : '0';
  }
  const h = keccak256(Buffer.from(id, 'utf8'));
  return (BigInt('0x' + h) % FIELD_PRIME).toString();
}

async function proveDecision(t, decision) {
  const input = {
    registeredVkHash: String(t.registered_vk),
    proofVkHash: String(t.proof_vk),
    minimum: String(t.minimum),
    publicBalance: String(t.public_balance),
    expiryBlock: String(t.expiry_block),
    currentBlock: String(t.current_block),
    recipient: String(t.recipient),
    conditionRecipient: String(t.condition_recipient),
    amount: String(t.amount),
    maxTransfer: String(t.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(t.task_id),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals };
}

// ---------- HTTP plumbing ----------
const responseCache = new Map(); // task_id -> response body string

function sendJson(res, status, bodyStr) {
  const headers = { 'Content-Type': 'application/json' };
  const sig = signOutbound(SECRET, bodyStr);
  if (sig) headers['x-agent-games-signature'] = sig;
  res.writeHead(status, headers);
  res.end(bodyStr);
}

async function handleGatekeeper(req, res, raw) {
  if (!verifyInbound(SECRET, raw, req.headers['x-agent-games-signature'])) {
    return sendJson(res, 401, JSON.stringify({ error: 'bad signature' }));
  }
  let task;
  try {
    task = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, JSON.stringify({ error: 'invalid json' }));
  }

  if (task && task.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, JSON.stringify({ ok: true, protocolVersion: 'v1' }));
  }

  const taskKey = String(task.task_id || '');
  if (taskKey && responseCache.has(taskKey)) {
    return sendJson(res, 200, responseCache.get(taskKey));
  }

  const { decision, reason } = decide(task);
  const out = { decision, reason_code: reason, proof_tx: task.proof_tx };

  if (reason !== 'PROOF_REUSED') {
    try {
      const { proof, publicSignals } = await proveDecision(task, decision);
      out.proof = proof;
      out.public_signals = publicSignals;
    } catch (err) {
      // Fail closed: return the decision without a proof rather than crash.
      console.error('proof generation failed:', err.message);
    }
  }

  const bodyStr = JSON.stringify(out);
  if (taskKey) responseCache.set(taskKey, bodyStr);
  console.log(new Date().toISOString(), taskKey, decision, reason, out.proof ? 'with proof' : 'NO PROOF');
  return sendJson(res, 200, bodyStr);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return sendJson(res, 200, JSON.stringify({
      ok: true, service: 'hexa-gatekeeper', hmacConfigured: Boolean(SECRET),
      taskIdMode: TASK_ID_MODE,
    }));
  }
  if (req.method === 'POST' && req.url === '/gatekeeper') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      handleGatekeeper(req, res, Buffer.concat(chunks)).catch((err) => {
        console.error('handler error:', err);
        try { sendJson(res, 500, JSON.stringify({ error: 'internal' })); } catch {}
      });
    });
    return;
  }
  return sendJson(res, 404, JSON.stringify({ error: 'not found' }));
});

// ---------- Circuit artifacts ----------
// The official circuit files are public and stable; fetch them at boot when
// they are not bundled (the git repo intentionally carries no binaries).
const CIRCUIT_URLS = {
  [WASM]: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm',
  [ZKEY]: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey',
};
function download(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(download(res.headers.location, dest, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`download ${url} -> HTTP ${res.statusCode}`));
      }
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    }).on('error', reject);
  });
}
async function ensureCircuits() {
  fs.mkdirSync(path.dirname(WASM), { recursive: true });
  for (const [file, url] of Object.entries(CIRCUIT_URLS)) {
    if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
      console.log('fetching circuit artifact:', url);
      await download(url, file);
    }
  }
}

ensureCircuits()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`hexa-gatekeeper listening on :${PORT} (hmac ${SECRET ? 'on' : 'OFF'})`);
    });
  })
  .catch((err) => {
    console.error('circuit setup failed:', err.message);
    process.exit(1);
  });
