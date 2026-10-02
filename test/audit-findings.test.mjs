// Regression tests, one per finding of the audit of 91407cb
// (https://api.imd.fun/jobs/ae3c9745-7363-4bd2-bfaf-dc8944649cd8/report.md).
// Everything runs offline: an injected fetch, a throwaway key and a temporary XDG_STATE_HOME.
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = mkdtempSync(join(tmpdir(), 'imd-sdk-findings-'));
process.env.XDG_STATE_HOME = ROOT;
const SDK = fileURLToPath(new URL('../src/index.js', import.meta.url));
const { ImdClient, LocalPrivateKeySigner, ImdError } = await import('../src/index.js');
const { signDigest, addressFromPrivateKey } = await import('../src/crypto.js');

const KEY = '0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412c8b4f11f99f37b';
const ASSET = '0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7';
const PAY_TO = '0x4e0fa57bde726079356537e2f34d671e9f41adbc';
const HALF = '500000000000000000';
const ORDER = 'order-1';
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const now = () => Math.floor(Date.now() / 1000);
const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

/** The audit's common challenge, built fresh so each test can mutate it. */
function challengeFor(amount, { expiresAt = now() + 600, action = 'job.open', id = ORDER } = {}) {
  const payment = { network: 'eip155:1', scheme: 'exact', asset: ASSET, amount, payTo: PAY_TO, decimals: 18 };
  const quote = { v: 1, id: 'quote-1', quoteHash: '22'.repeat(32), action, payment, expiresAt, issuedAt: expiresAt - 600 };
  return {
    x402Version: 2,
    quote,
    accepts: [{ scheme: 'exact', network: 'eip155:1', asset: ASSET, amount, payTo: PAY_TO, maxTimeoutSeconds: 60, extra: { assetTransferMethod: 'permit2' } }],
    resource: { url: `https://api.example/requests/${id}`, description: 'job', mimeType: 'application/json' },
    resourceUrl: `https://api.example/requests/${id}`,
    requesterScopeHash: '11'.repeat(32),
    input: {},
  };
}
function capabilitiesFor(action, amount) {
  return { actions: [{ action, payment: { network: 'eip155:1', asset: ASSET, amount, payTo: PAY_TO, decimals: 18 }, quoteTtlSeconds: 600 }], pricedPer: { 'schedule.create': 'run', 'schedule.topup': 'run' }, payment: { x402Version: 2, scheme: 'exact', assetTransferMethod: 'permit2' } };
}
/** A deterministic in-process service: 402 on the unsigned submit, 202 on the signed one, status quoted until paid. */
function mock(amount, overrides = {}) {
  const challenge = challengeFor(amount);
  const state = { challenge, capabilities: capabilitiesFor('job.open', amount), status: { status: 'quoted', order: { id: ORDER, status: 'quoted', quote: challenge.quote }, payment: null, admission: null }, quoteResponse: { created: true, order: { id: ORDER, status: 'quoted', quote: challenge.quote } }, posts: [], challenges: 0, statusReads: 0, onPaid: undefined, ...overrides };
  state.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname, headers = init.headers || {};
    if (path === '/requests/capabilities') return json(200, state.capabilities);
    if (path === '/requests/quote') return json(201, state.quoteResponse);
    if (path === `/requests/${ORDER}/submit` && !headers['PAYMENT-SIGNATURE']) { state.challenges++; return json(402, state.challenge); }
    if (path === `/requests/${ORDER}/submit`) {
      const post = { header: headers['PAYMENT-SIGNATURE'], payment: JSON.parse(Buffer.from(headers['PAYMENT-SIGNATURE'], 'base64').toString()), quoteSignature: JSON.parse(init.body).quoteSignature };
      state.posts.push(post);
      if (state.onPaid) return state.onPaid(post);
      state.status = { status: 'payment_pending', order: { id: ORDER, status: 'payment_pending', quote: state.challenge.quote }, payment: null, admission: null };
      return json(202, { status: 'payment_pending', order: { id: ORDER } });
    }
    if (path === `/requests/${ORDER}`) { state.statusReads++; return json(200, state.status); }
    return json(404, { error: 'not_found' });
  };
  return state;
}
/** Counting signer wrapping the real local signer; records every typed-data object. */
function countingSigner(fail) {
  const real = new LocalPrivateKeySigner(KEY);
  const typed = [];
  return { typed, address: real.address, async signTypedData(data) { if (fail) throw fail; typed.push(data); return real.signTypedData(data); } };
}
/** Each client gets its own state directory, which is what a fresh machine or a wiped state looks like. */
function freshClient(m, options = {}) {
  process.env.XDG_STATE_HOME = mkdtempSync(join(ROOT, 'state-'));
  return new ImdClient({ baseUrl: 'https://api.example', fetch: m.fetch, ...options });
}
const stateDir = (client) => join(client.spendFile, '..');
const ledgerOf = (client) => { try { return JSON.parse(readFileSync(client.spendFile, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return undefined; throw e; } };
const today = () => new Date().toISOString().slice(0, 10);
const rejects = (p, re) => assert.rejects(p, (e) => { assert.match(e.message, re); return true; });

test('finding 1: a retry of an unresolved order reuses the persisted authorization and never signs a second Permit2', async () => {
  const m = mock(HALF);
  const signer = countingSigner();
  const client = freshClient(m);
  // Delivery with a lost reply: the paid POST reaches the service but the response never arrives.
  m.onPaid = () => { throw new TypeError('fetch failed after upload'); };
  await assert.rejects(client.pay(ORDER, signer, { execute: true }), TypeError);
  assert.equal(signer.typed.length, 2);
  assert.equal(m.posts.length, 1);
  const files = readdirSync(stateDir(client)).filter((f) => f.startsWith('order-') && f.endsWith('.json'));
  assert.equal(files.length, 1, 'the signed payload is persisted next to the spend ledger');
  assert.equal(statSync(join(stateDir(client), files[0])).mode & 0o777, 0o600);
  // The service recorded the payment: the retry must reconcile through GET /requests/{id} and sign nothing.
  m.status = { status: 'payment_pending', order: { id: ORDER, quote: m.challenge.quote } };
  const reconciled = await client.pay(ORDER, signer, { execute: true });
  assert.equal(reconciled.status, 'payment_pending');
  assert.equal(signer.typed.length, 2, 'no new signatures when the order is already paying');
  assert.equal(m.posts.length, 1);
  // The service still says quoted: the retry resubmits the exact same payload, same nonce, same signatures.
  m.status = { status: 'quoted', order: { id: ORDER, quote: m.challenge.quote } };
  m.onPaid = undefined;
  const second = await client.pay(ORDER, signer, { execute: true });
  assert.equal(second.status, 'payment_pending');
  assert.equal(signer.typed.length, 2, 'retry never signs a second authorization');
  assert.equal(m.posts.length, 2);
  assert.equal(m.posts[1].header, m.posts[0].header);
  assert.equal(m.posts[1].quoteSignature, m.posts[0].quoteSignature);
  assert.equal(m.posts[1].payment.payload.permit2Authorization.nonce, m.posts[0].payment.payload.permit2Authorization.nonce);
  assert.equal(ledgerOf(client)[today()], HALF, 'one reservation for one authorization');
  // A second process with no saved payload still checks status before signing anything.
  const other = new ImdClient({ baseUrl: 'https://api.example', fetch: m.fetch });
  rmSync(join(stateDir(other), files[0]), { force: true });
  const seen = await other.pay(ORDER, signer, { execute: true });
  assert.equal(seen.status, 'payment_pending');
  assert.equal(signer.typed.length, 2);
  // Concurrent calls on the same order in one process are serialized: one signs, the other reconciles.
  const m2 = mock(HALF);
  const s2 = countingSigner();
  const c2 = freshClient(m2);
  const results = await Promise.all([c2.pay(ORDER, s2, { execute: true }), c2.pay(ORDER, s2, { execute: true })]);
  assert.equal(s2.typed.length, 2);
  assert.equal(m2.posts.length, 1);
  assert.ok(results.every((r) => r.status === 'payment_pending'));
});

test('finding 2: the daily cap holds across processes: exclusive lock, atomic write, fail closed on a corrupt ledger', async () => {
  // (a) An exclusive lock held by another process blocks the read-check-write and nothing is signed meanwhile.
  const m = mock('300000000000000000');
  const signer = countingSigner();
  const client = freshClient(m);
  mkdirSync(stateDir(client), { recursive: true });
  const lock = `${client.spendFile}.lock`;
  writeFileSync(lock, '12345');
  const inFlight = client.pay(ORDER, signer, { execute: true });
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(signer.typed.length, 0, 'nothing is signed while the ledger lock is held');
  assert.equal(ledgerOf(client), undefined);
  rmSync(lock);
  assert.equal((await inFlight).status, 'payment_pending');
  assert.equal(signer.typed.length, 2);
  // (b) The write is atomic: a valid ledger, no temp files left behind, mode 0600.
  assert.deepEqual(ledgerOf(client), { [today()]: '300000000000000000' });
  assert.deepEqual(readdirSync(stateDir(client)).filter((f) => f.endsWith('.tmp') || f.endsWith('.lock')), []);
  assert.equal(statSync(client.spendFile).mode & 0o777, 0o600);
  // (c) A truncated or malformed ledger fails closed instead of resetting the cap.
  for (const corrupt of ['', '{"2026-01-01":1}', '[]', 'null', '{bad json']) {
    const mm = mock('300000000000000000');
    const ss = countingSigner();
    const cc = freshClient(mm);
    mkdirSync(stateDir(cc), { recursive: true });
    writeFileSync(cc.spendFile, corrupt);
    await rejects(cc.pay(ORDER, ss, { execute: true }), /ledger (corrupt|unreadable); refusing to sign/);
    assert.equal(ss.typed.length, 0);
    assert.equal(readFileSync(cc.spendFile, 'utf8'), corrupt, 'a corrupt ledger is never overwritten');
  }
  // (d) Two real processes racing on one ledger: exactly one 0.3 IMD authorization fits under the 0.5 IMD day cap.
  const dir = mkdtempSync(join(ROOT, 'race-'));
  const script = join(dir, 'child.mjs');
  writeFileSync(script, `
    import { ImdClient, LocalPrivateKeySigner } from ${JSON.stringify(SDK)};
    const json=(s,v)=>new Response(JSON.stringify(v),{status:s});
    const [order,amount]=process.argv.slice(2);
    const now=Math.floor(Date.now()/1000);
    const payment={network:'eip155:1',scheme:'exact',asset:${JSON.stringify(ASSET)},amount,payTo:${JSON.stringify(PAY_TO)},decimals:18};
    const quote={id:'quote-'+order,quoteHash:'22'.repeat(32),action:'job.open',payment,expiresAt:now+600};
    const challenge={x402Version:2,quote,accepts:[{scheme:'exact',network:'eip155:1',asset:payment.asset,amount,payTo:payment.payTo,maxTimeoutSeconds:60,extra:{assetTransferMethod:'permit2'}}],resource:{url:'https://api.example/requests/'+order},resourceUrl:'https://api.example/requests/'+order,requesterScopeHash:'11'.repeat(32),input:{}};
    let signed=0;const real=new LocalPrivateKeySigner(${JSON.stringify(KEY)});
    const signer={address:real.address,signTypedData:(t)=>{signed++;return real.signTypedData(t);}};
    const fetch=async(url,init={})=>{const p=new URL(url).pathname,h=init.headers||{};
      if(p==='/requests/capabilities')return json(200,{actions:[{action:'job.open',payment}],pricedPer:{},payment:{scheme:'exact',assetTransferMethod:'permit2'}});
      if(p.endsWith('/submit')&&!h['PAYMENT-SIGNATURE'])return json(402,challenge);
      if(p.endsWith('/submit'))return json(202,{status:'payment_pending'});
      return json(200,{status:'quoted',order:{id:order,quote}});};
    const client=new ImdClient({baseUrl:'https://api.example',fetch,signer});
    const go=new Promise(r=>process.on('message',m=>m==='go'&&r()));process.send('ready');await go;
    try{const out=await client.pay(order,signer,{execute:true});process.send({ok:true,status:out.status,signed});}
    catch(e){process.send({ok:false,error:e.message,signed});}
  `);
  const home = mkdtempSync(join(ROOT, 'race-state-'));
  const children = ['order-a', 'order-b', 'order-c'].map((o) => fork(script, [o, '300000000000000000'], { env: { ...process.env, XDG_STATE_HOME: home }, stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
  let ready = 0;
  const results = await Promise.all(children.map((child) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('child timed out')), 30000);
    child.on('message', (msg) => {
      if (msg === 'ready') { if (++ready === children.length) for (const c of children) c.send('go'); return; }
      clearTimeout(timer); resolve(msg); child.kill();
    });
    child.on('error', reject);
  })));
  const ok = results.filter((r) => r.ok);
  assert.equal(ok.length, 1, `exactly one process may authorize: ${JSON.stringify(results)}`);
  assert.ok(results.filter((r) => !r.ok).every((r) => /daily IMD spending cap exceeded/.test(r.error) && r.signed === 0), JSON.stringify(results));
  assert.deepEqual(JSON.parse(readFileSync(join(home, 'imd-sdk', 'daily-spend.json'), 'utf8')), { [today()]: '300000000000000000' });
});

test('finding 3: an unchanged quote passes whether it was saved flat or nested as quote.payment', async () => {
  // The real quote response nests the quote under order.quote with a payment object.
  const m = mock(HALF);
  const signer = countingSigner();
  const client = freshClient(m);
  const quoted = await client.quote('job.open', { objective: 'test' });
  assert.equal(quoted.order.quote.payment.amount, HALF);
  const paid = await client.pay(ORDER, signer, { execute: true });
  assert.equal(paid.status, 'payment_pending');
  assert.equal(signer.typed.length, 2);
  // { order: { id }, quote } with a nested payment also passes.
  const m2 = mock(HALF, { quoteResponse: { order: { id: ORDER }, quote: challengeFor(HALF).quote } });
  const s2 = countingSigner();
  const c2 = freshClient(m2);
  await c2.quote('job.open', {});
  assert.equal((await c2.pay(ORDER, s2, { execute: true })).status, 'payment_pending');
  assert.equal(s2.typed.length, 2);
  // A fresh client that only has the nested status response also passes.
  const m3 = mock(HALF);
  const s3 = countingSigner();
  const c3 = freshClient(m3);
  assert.equal((await c3.pay(ORDER, s3, { execute: true })).status, 'payment_pending');
  assert.equal(s3.typed.length, 2);
});

test('finding 4: validation runs before reserving budget; pre-authorization failures release it; submitted attempts stay reserved', async () => {
  // A quote that expires too soon is refused without touching the budget.
  const m = mock(HALF);
  m.challenge = challengeFor(HALF, { expiresAt: now() + 4 });
  m.status.order.quote = m.challenge.quote;
  const signer = countingSigner();
  const client = freshClient(m);
  await rejects(client.pay(ORDER, signer, { execute: true }), /expires too soon/);
  assert.equal(signer.typed.length, 0);
  assert.equal(ledgerOf(client), undefined, 'nothing reserved before the inputs are valid');
  m.challenge = challengeFor(HALF);
  m.status.order.quote = m.challenge.quote;
  assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending', 'the day budget is still available');
  // A signer that refuses releases the reservation; the next payment fits.
  const m2 = mock(HALF);
  const c2 = freshClient(m2);
  await rejects(c2.pay(ORDER, countingSigner(new Error('user rejected on device')), { execute: true }), /user rejected on device/);
  assert.equal(ledgerOf(c2)[today()], '0');
  const s2 = countingSigner();
  assert.equal((await c2.pay(ORDER, s2, { execute: true })).status, 'payment_pending');
  assert.equal(s2.typed.length, 2);
  assert.equal(ledgerOf(c2)[today()], HALF);
  // A submitted attempt with an ambiguous outcome keeps its reservation until reconciled.
  const m3 = mock(HALF);
  m3.onPaid = () => { throw new TypeError('fetch failed after upload'); };
  const c3 = freshClient(m3);
  await assert.rejects(c3.pay(ORDER, countingSigner(), { execute: true }), TypeError);
  assert.equal(ledgerOf(c3)[today()], HALF, 'an authorization that may have left the process stays reserved');
  const m4 = mock(HALF);
  m4.onPaid = () => json(402, { error: 'payment_rejected' });
  const c4 = freshClient(m4);
  await assert.rejects(c4.pay(ORDER, countingSigner(), { execute: true }), ImdError);
  assert.equal(ledgerOf(c4)[today()], HALF, 'a rejected but exposed authorization stays reserved');
  // A signer without a usable address is refused before anything is reserved.
  const m5 = mock(HALF);
  const c5 = freshClient(m5);
  await rejects(c5.pay(ORDER, { address: 'not-an-address', signTypedData: async () => '0x' }, { execute: true }), /signer must expose an address/);
  assert.equal(ledgerOf(c5), undefined);
});

test('finding 5: only eip155:1 exact permit2 terms are signed, consistently across challenge, quote and capabilities', async () => {
  const cases = [
    ['sepolia network', (ch) => { ch.accepts[0].network = 'eip155:11155111'; ch.quote.payment.network = 'eip155:11155111'; }],
    ['upto scheme', (ch) => { ch.accepts[0].scheme = 'upto'; }],
    ['eip3009 transfer method', (ch) => { ch.accepts[0].extra.assetTransferMethod = 'eip3009'; }],
    ['missing transfer method', (ch) => { delete ch.accepts[0].extra; }],
    ['quote network differs from challenge', (ch) => { ch.quote.payment.network = 'eip155:8453'; }],
    ['quote scheme differs', (ch) => { ch.quote.payment.scheme = 'upto'; }],
  ];
  for (const [name, mutate] of cases) {
    const m = mock('100000000000000000');
    mutate(m.challenge);
    m.status.order.quote = m.challenge.quote;
    const signer = countingSigner();
    const client = freshClient(m);
    await rejects(client.pay(ORDER, signer, { execute: true }), /refusing to sign/);
    assert.equal(signer.typed.length, 0, `${name}: nothing signed`);
    assert.equal(m.posts.length, 0, `${name}: nothing submitted`);
    assert.equal(ledgerOf(client), undefined, `${name}: nothing reserved`);
  }
  for (const [name, mutate] of [
    ['capabilities network', (caps) => { caps.actions[0].payment.network = 'eip155:11155111'; }],
    ['capabilities scheme', (caps) => { caps.payment.scheme = 'upto'; }],
    ['capabilities transfer method', (caps) => { caps.payment.assetTransferMethod = 'eip3009'; }],
  ]) {
    const m = mock('100000000000000000');
    mutate(m.capabilities);
    const signer = countingSigner();
    await rejects(freshClient(m).pay(ORDER, signer, { execute: true }), /refusing to sign/);
    assert.equal(signer.typed.length, 0, name);
  }
  const m = mock('100000000000000000');
  const signer = countingSigner();
  assert.equal((await freshClient(m).pay(ORDER, signer, { execute: true })).status, 'payment_pending', 'unchanged mainnet terms still pay');
  assert.equal(signer.typed[0].domain.chainId, 1);
});

test('finding 6: the Permit2 deadline is min(quote.expiresAt - 5, now + maxTimeoutSeconds) with a positive bounded timeout', async () => {
  const m = mock('100000000000000000');
  const signer = countingSigner();
  const client = freshClient(m);
  const before = now();
  await client.pay(ORDER, signer, { execute: true });
  const after = now();
  const signedDeadline = signer.typed[0].message.deadline;
  const sentDeadline = BigInt(m.posts[0].payment.payload.permit2Authorization.deadline);
  assert.equal(signedDeadline, sentDeadline);
  assert.ok(sentDeadline >= BigInt(before + 60) && sentDeadline <= BigInt(after + 60), `deadline ${sentDeadline} is bounded by now + 60`);
  assert.ok(sentDeadline < BigInt(m.challenge.quote.expiresAt - 5));
  // A quote that expires before the timeout window bounds the deadline by expiresAt - 5.
  const m2 = mock('100000000000000000');
  m2.challenge = challengeFor('100000000000000000', { expiresAt: now() + 30 });
  m2.status.order.quote = m2.challenge.quote;
  const s2 = countingSigner();
  await freshClient(m2).pay(ORDER, s2, { execute: true });
  assert.equal(s2.typed[0].message.deadline, BigInt(m2.challenge.quote.expiresAt - 5));
  // Non-positive, non-integer or absurd timeouts are refused before signing.
  for (const timeout of [0, -1, 1.5, '60', undefined, 10 ** 9]) {
    const mm = mock('100000000000000000');
    mm.challenge.accepts[0].maxTimeoutSeconds = timeout;
    const ss = countingSigner();
    await rejects(freshClient(mm).pay(ORDER, ss, { execute: true }), /invalid payment timeout/);
    assert.equal(ss.typed.length, 0);
  }
});

test('finding 7: QuoteApproval is bound to the saved quote id, hash, asset and the selected order resource; missing original fails closed', async () => {
  // The saved quote is flat; the challenge keeps every visible term but swaps the quote identity.
  const flat = { id: 'quote-1', quoteHash: '22'.repeat(32), action: 'job.open', asset: ASSET, amount: '100000000000000000', payTo: PAY_TO, expiresAt: now() + 600 };
  const m = mock('100000000000000000', { quoteResponse: { order: { id: ORDER }, quote: flat } });
  m.challenge.quote.expiresAt = flat.expiresAt;
  m.challenge.quote.id = 'quote-ATTACK';
  m.challenge.quote.quoteHash = 'aa'.repeat(32);
  const signer = countingSigner();
  const client = freshClient(m);
  await client.quote('job.open', { objective: 'review A' });
  await rejects(client.pay(ORDER, signer, { execute: true }), /differs from the original quote/);
  assert.equal(signer.typed.length, 0);
  // Same identity, different asset in the saved quote: refused.
  const m2 = mock('100000000000000000', { quoteResponse: { order: { id: ORDER }, quote: { ...flat, asset: PAY_TO } } });
  m2.challenge.quote.expiresAt = flat.expiresAt;
  const c2 = freshClient(m2);
  await c2.quote('job.open', {});
  await rejects(c2.pay(ORDER, countingSigner(), { execute: true }), /differs from the original quote/);
  // No original quote anywhere: fail closed instead of signing whatever the challenge says.
  const m3 = mock('100000000000000000');
  m3.status = { status: 'quoted' };
  const s3 = countingSigner();
  await rejects(freshClient(m3).pay(ORDER, s3, { execute: true }), /original quote missing/);
  assert.equal(s3.typed.length, 0);
  // A challenge whose resource is another order is refused.
  const m4 = mock('100000000000000000');
  m4.challenge.resourceUrl = 'https://api.example/requests/order-9';
  m4.challenge.resource.url = m4.challenge.resourceUrl;
  const s4 = countingSigner();
  await rejects(freshClient(m4).pay(ORDER, s4, { execute: true }), /not the selected order/);
  assert.equal(s4.typed.length, 0);
  // On the happy path the approval carries the saved quote's identity and the order's resource.
  const m5 = mock('100000000000000000', { quoteResponse: { order: { id: ORDER }, quote: flat } });
  m5.challenge.quote.expiresAt = flat.expiresAt;
  const s5 = countingSigner();
  const c5 = freshClient(m5);
  await c5.quote('job.open', {});
  await c5.pay(ORDER, s5, { execute: true });
  const approval = s5.typed[1];
  assert.equal(approval.primaryType, 'QuoteApproval');
  assert.equal(approval.message.quoteId, 'quote-1');
  assert.equal(approval.message.quoteHash, `0x${'22'.repeat(32)}`);
  assert.equal(approval.message.asset, ASSET);
  assert.equal(approval.message.resource, `https://api.example/requests/${ORDER}`);
});

test('finding 8: schedule.create and schedule.topup are priced per run: total = runs x unitAmount, runs match the request, caps apply to the total', async () => {
  const ONE = '1000000000000000000';
  for (const action of ['schedule.create', 'schedule.topup']) {
    const m = mock(ONE);
    m.challenge = challengeFor(ONE, { action });
    Object.assign(m.challenge.quote, { runs: 2, unitAmount: HALF });
    m.challenge.input = { runs: 2 };
    m.status.order.quote = m.challenge.quote;
    m.capabilities = capabilitiesFor(action, HALF);
    const signer = countingSigner();
    const client = freshClient(m, { maxPerRequest: '2000000000000000000', maxPerDay: '2000000000000000000' });
    assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending', action);
    assert.equal(signer.typed.length, 2);
    assert.equal(m.posts[0].payment.payload.permit2Authorization.permitted.amount, ONE);
    assert.equal(ledgerOf(client)[today()], ONE, 'the whole total is reserved');
  }
  const bad = [
    ['runs differ from the request', (ch) => { ch.input = { runs: 3 }; }, /run count differs from the request/],
    ['runs differ from the saved quote', (ch, st) => { st.order.quote = { ...ch.quote, runs: 3 }; }, /differs from the original quote/],
    ['total is not runs x unitAmount', (ch) => { ch.accepts[0].amount = '900000000000000000'; ch.quote.payment.amount = '900000000000000000'; }, /differ from quote or capabilities/],
    ['unit price differs from capabilities', (ch) => { ch.quote.unitAmount = '450000000000000000'; ch.accepts[0].amount = '900000000000000000'; ch.quote.payment.amount = '900000000000000000'; }, /unit price differs/],
    ['missing run count', (ch) => { delete ch.quote.runs; }, /missing a valid run count/],
  ];
  for (const [name, mutate, re] of bad) {
    const m = mock(ONE);
    m.challenge = challengeFor(ONE, { action: 'schedule.create' });
    Object.assign(m.challenge.quote, { runs: 2, unitAmount: HALF });
    m.challenge.input = { runs: 2 };
    m.status.order.quote = m.challenge.quote;
    mutate(m.challenge, m.status);
    m.capabilities = capabilitiesFor('schedule.create', HALF);
    const signer = countingSigner();
    await rejects(freshClient(m, { maxPerRequest: '2000000000000000000', maxPerDay: '2000000000000000000' }).pay(ORDER, signer, { execute: true }), re);
    assert.equal(signer.typed.length, 0, name);
  }
  // Caps apply to the total, not the unit price: two runs of 0.5 IMD exceed the default 0.5 IMD per-request cap.
  const m = mock(ONE);
  m.challenge = challengeFor(ONE, { action: 'schedule.create' });
  Object.assign(m.challenge.quote, { runs: 2, unitAmount: HALF });
  m.status.order.quote = m.challenge.quote;
  m.capabilities = capabilitiesFor('schedule.create', HALF);
  const signer = countingSigner();
  await rejects(freshClient(m).pay(ORDER, signer, { execute: true }), /per-request IMD spending cap exceeded/);
  assert.equal(signer.typed.length, 0);
});

test('finding 9: a challenge without a resource is refused before reserving or signing, and the payment header is always valid JSON', async () => {
  const m = mock('100000000000000000');
  delete m.challenge.resource;
  const signer = countingSigner();
  const client = freshClient(m);
  await rejects(client.pay(ORDER, signer, { execute: true }), /resource missing; refusing to sign/);
  assert.equal(signer.typed.length, 0);
  assert.equal(m.posts.length, 0);
  assert.equal(ledgerOf(client), undefined);
  const m2 = mock('100000000000000000');
  m2.challenge.resourceUrl = '';
  await rejects(freshClient(m2).pay(ORDER, countingSigner(), { execute: true }), /resource missing; refusing to sign/);
  const m3 = mock('100000000000000000');
  await freshClient(m3).pay(ORDER, countingSigner(), { execute: true });
  const text = Buffer.from(m3.posts[0].header, 'base64').toString();
  assert.doesNotMatch(text, /undefined/);
  assert.deepEqual(JSON.parse(text).resource, m3.challenge.resource);
  assert.deepEqual(Object.keys(JSON.parse(text)).sort(), ['accepted', 'payload', 'resource', 'x402Version']);
});

test('finding 10: signDigest and addressFromPrivateKey normalize the key and throw a static error without key material', () => {
  const bare = 'ab'.repeat(32);
  const digest = new Uint8Array(32).fill(7);
  assert.equal(addressFromPrivateKey(bare), addressFromPrivateKey(`0x${bare}`));
  assert.equal(signDigest(bare, digest), signDigest(`0x${bare}`, digest));
  assert.equal(addressFromPrivateKey(bare), new LocalPrivateKeySigner(bare).address);
  for (const key of ['zz'.repeat(32), 'ab'.repeat(31), `0x${'ab'.repeat(33)}`, '0x', '', 12345, null, undefined, { key: bare }, `0x${N.toString(16)}`, `0x${'0'.repeat(64)}`]) {
    for (const fn of [() => signDigest(key, digest), () => addressFromPrivateKey(key)]) {
      let error;
      try { fn(); } catch (e) { error = e; }
      assert.ok(error instanceof Error, 'rejects');
      assert.equal(error.message, 'invalid private key');
      if (typeof key === 'string' && key.length > 8) assert.ok(!error.message.includes(key.slice(-8)) && !String(error.stack).includes(key.slice(-8)), 'no key material in the error');
    }
  }
});

test('finding 11: LocalPrivateKeySigner rejects scalars outside 0 < d < N before exposing an address', async () => {
  const hex = (n) => `0x${n.toString(16).padStart(64, '0')}`;
  for (const bad of [hex(N + 5n), hex(N), hex(0n), hex(N - 1n + 1n), `0x${'f'.repeat(64)}`]) {
    assert.throws(() => new LocalPrivateKeySigner(bad), { message: 'invalid private key' });
  }
  const five = new LocalPrivateKeySigner(hex(5n));
  assert.equal(five.address, '0xe1ab8145f7e55dc933d51a18c793f901a3a0b276', 'scalar 5 is the address the overflowed key used to publish');
  const edge = new LocalPrivateKeySigner(hex(N - 1n));
  assert.match(edge.address, /^0x[0-9a-f]{40}$/);
  const typed = { domain: { name: 'test', chainId: 1 }, primaryType: 'T', types: { T: [{ name: 'x', type: 'uint256' }] }, message: { x: 1n } };
  assert.match(await edge.signTypedData(typed), /^0x[0-9a-f]{130}$/, 'every accepted key can sign');
  assert.equal(new LocalPrivateKeySigner(hex(1n)).address, '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
});
