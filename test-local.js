// Local end-to-end test for hexa-gatekeeper: starts the server, sends a
// preflight, a valid task (expect APPROVE + verifiable proof), a trap task
// (expect REJECT + verifiable proof), and a proof-reuse task (expect
// PROOF_REUSED with no proof).
const { spawn } = require('child_process');
const snarkjs = require('snarkjs');
const path = require('path');
const fs = require('fs');

const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';

function task(overrides) {
  return {
    task_id: 'gk_test_1',
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: '2000',
    current_block: '1500',
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0x' + 'aa'.repeat(32),
    ...overrides,
  };
}

async function post(body) {
  const res = await fetch('http://127.0.0.1:8080/gatekeeper', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

async function main() {
  const server = spawn('node', ['server.js'], { stdio: 'pipe' });
  server.stdout.on('data', (d) => process.stdout.write('[srv] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[srv-err] ' + d));
  await new Promise((r) => setTimeout(r, 1500));
  try {
    const health = await (await fetch('http://127.0.0.1:8080/health')).json();
    console.log('health:', JSON.stringify(health));

    const pre = await post({ type: 'agent-games.preflight.v1' });
    console.log('preflight:', pre.status, JSON.stringify(pre.json));

    // Export the verification key once for local proof checks.
    const vkPath = path.join(__dirname, 'vk.json');
    const quiet = { info: () => {}, debug: () => {}, warn: () => {}, error: () => {} };
    if (!fs.existsSync(vkPath)) {
      const exported = await snarkjs.zKey.exportVerificationKey(
        path.join(__dirname, 'circuits', 'gatekeeper_final.zkey'), quiet);
      fs.writeFileSync(vkPath, JSON.stringify(exported));
    }
    const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));

    const t1 = await post(task({}));
    console.log('valid task:', t1.status, t1.json.decision, t1.json.reason_code,
      'signals:', t1.json.public_signals && t1.json.public_signals.length);
    if (t1.json.proof) {
      const ok = await snarkjs.groth16.verify(vk, t1.json.public_signals, t1.json.proof, quiet);
      console.log('valid task proof verifies:', ok);
    }

    const t2 = await post(task({
      task_id: 'gk_test_2', recipient: OTHER, proof_tx: '0x' + 'bb'.repeat(32),
    }));
    console.log('trap task:', t2.status, t2.json.decision, t2.json.reason_code,
      'signals:', t2.json.public_signals && t2.json.public_signals.length);
    if (t2.json.proof) {
      const ok = await snarkjs.groth16.verify(vk, t2.json.public_signals, t2.json.proof, quiet);
      console.log('trap task proof verifies:', ok);
    }

    const t3 = await post(task({ task_id: 'gk_test_3' })); // same proof_tx as t1
    console.log('reuse task:', t3.status, t3.json.decision, t3.json.reason_code,
      'has proof:', Boolean(t3.json.proof));
  } finally {
    server.kill();
  }
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
