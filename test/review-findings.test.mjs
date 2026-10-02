// Regression tests for the review of the audit fixes (d4ce9ed): the per-order and ledger locks, the saved
// authorization record and the deadline grace. Everything runs offline with an injected fetch, a throwaway
// key and temporary XDG_STATE_HOME directories. Each test fails on d4ce9ed and passes now.
import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = mkdtempSync(join(tmpdir(), 'imd-sdk-review-'));
process.env.XDG_STATE_HOME = ROOT;
const SDK = fileURLToPath(new URL('../src/index.js', import.meta.url));
const { ImdClient, LocalPrivateKeySigner } = await import('../src/index.js');

const KEY = '0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412c8b4f11f99f37b';
const ASSET = '0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7';
const PAY_TO = '0x4e0fa57bde726079356537e2f34d671e9f41adbc';
const QUARTER = '250000000000000000';
const TENTH = '100000000000000000';
const ORDER = 'order-1';
const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const today = () => new Date().toISOString().slice(0, 10);
const rejects = (p, re) => assert.rejects(p, (e) => { assert.match(e.message, re); return true; });

function challengeFor(amount) {
  const payment = { network: 'eip155:1', scheme: 'exact', asset: ASSET, amount, payTo: PAY_TO, decimals: 18 };
  const quote = { v: 1, id: 'quote-1', quoteHash: '22'.repeat(32), action: 'job.open', payment, expiresAt: now() + 600 };
  return {
    x402Version: 2,
    quote,
    accepts: [{ scheme: 'exact', network: 'eip155:1', asset: ASSET, amount, payTo: PAY_TO, maxTimeoutSeconds: 60, extra: { assetTransferMethod: 'permit2' } }],
    resource: { url: `https://api.example/requests/${ORDER}`, description: 'job', mimeType: 'application/json' },
    resourceUrl: `https://api.example/requests/${ORDER}`,
    requesterScopeHash: '11'.repeat(32),
    input: {},
  };
}
/** In-process service: 402 on the unsigned submit, 202 on the signed one, status quoted until paid; capabilities can stall. */
function mock(amount) {
  const challenge = challengeFor(amount);
  const state = { challenge, capabilitiesDelayMs: 0, posts: [], quoted() { state.status = { status: 'quoted', order: { id: ORDER, status: 'quoted', quote: challenge.quote } }; } };
  state.quoted();
  state.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname, headers = init.headers || {};
    if (path === '/requests/capabilities') {
      if (state.capabilitiesDelayMs) await sleep(state.capabilitiesDelayMs);
      return json(200, { actions: [{ action: 'job.open', payment: challenge.quote.payment }], pricedPer: {}, payment: { x402Version: 2, scheme: 'exact', assetTransferMethod: 'permit2' } });
    }
    if (path === `/requests/${ORDER}/submit` && !headers['PAYMENT-SIGNATURE']) return json(402, state.challenge);
    if (path === `/requests/${ORDER}/submit`) {
      state.posts.push({ header: headers['PAYMENT-SIGNATURE'], payment: JSON.parse(Buffer.from(headers['PAYMENT-SIGNATURE'], 'base64').toString()), quoteSignature: JSON.parse(init.body).quoteSignature });
      state.status = { status: 'payment_pending', order: { id: ORDER, status: 'payment_pending', quote: challenge.quote } };
      return json(202, { status: 'payment_pending', order: { id: ORDER } });
    }
    if (path === `/requests/${ORDER}`) return json(200, state.status);
    return json(404, { error: 'not_found' });
  };
  return state;
}
function countingSigner() {
  const real = new LocalPrivateKeySigner(KEY);
  const typed = [];
  return { typed, address: real.address, async signTypedData(data) { typed.push(data); return real.signTypedData(data); } };
}
function freshClient(m) {
  process.env.XDG_STATE_HOME = mkdtempSync(join(ROOT, 'state-'));
  return new ImdClient({ baseUrl: 'https://api.example', fetch: m.fetch });
}
const ledgerOf = (client) => { try { return JSON.parse(readFileSync(client.spendFile, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return undefined; throw e; } };
const nonceOf = (post) => post.payment.payload.permit2Authorization.nonce;
const ownerOf = (lockDir) => join(lockDir, readdirSync(lockDir).find((f) => f.startsWith('owner-')));

/** A separate imd-sdk process paying `order` against its own mock (status always quoted), reporting signatures and submitted nonces. */
const CHILD = join(ROOT, 'child.mjs');
writeFileSync(CHILD, `
  import { ImdClient, LocalPrivateKeySigner } from ${JSON.stringify(SDK)};
  const json=(s,v)=>new Response(JSON.stringify(v),{status:s});
  const [order,amount]=process.argv.slice(2);
  const now=Math.floor(Date.now()/1000);
  const payment={network:'eip155:1',scheme:'exact',asset:${JSON.stringify(ASSET)},amount,payTo:${JSON.stringify(PAY_TO)},decimals:18};
  const quote={id:'quote-1',quoteHash:'22'.repeat(32),action:'job.open',payment,expiresAt:now+600};
  const challenge={x402Version:2,quote,accepts:[{scheme:'exact',network:'eip155:1',asset:payment.asset,amount,payTo:payment.payTo,maxTimeoutSeconds:60,extra:{assetTransferMethod:'permit2'}}],resource:{url:'https://api.example/requests/'+order},resourceUrl:'https://api.example/requests/'+order,requesterScopeHash:'11'.repeat(32),input:{}};
  let signed=0;const real=new LocalPrivateKeySigner(${JSON.stringify(KEY)});
  const signer={address:real.address,signTypedData:(t)=>{signed++;return real.signTypedData(t);}};
  const nonces=[];
  const fetch=async(url,init={})=>{const p=new URL(url).pathname,h=init.headers||{};
    if(p==='/requests/capabilities')return json(200,{actions:[{action:'job.open',payment}],pricedPer:{},payment:{scheme:'exact',assetTransferMethod:'permit2'}});
    if(p.endsWith('/submit')&&!h['PAYMENT-SIGNATURE'])return json(402,challenge);
    if(p.endsWith('/submit')){nonces.push(JSON.parse(Buffer.from(h['PAYMENT-SIGNATURE'],'base64').toString()).payload.permit2Authorization.nonce);return json(202,{status:'payment_pending'});}
    return json(200,{status:'quoted',order:{id:order,quote}});};
  const client=new ImdClient({baseUrl:'https://api.example',fetch});
  const go=new Promise(r=>process.on('message',m=>m==='go'&&r()));process.send('ready');await go;
  try{const out=await client.pay(order,signer,{execute:true});process.send({ok:true,status:out.status,signed,nonces});}
  catch(e){process.send({ok:false,error:e.message,signed,nonces});}
`);
/** Fork children that start together once all are ready; resolves with their reports. */
function race(home, orders, amount, timeoutMs = 30000) {
  const children = orders.map((o) => fork(CHILD, [o, amount], { env: { ...process.env, XDG_STATE_HOME: home }, stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
  let ready = 0;
  return Promise.all(children.map((child) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('child timed out')); }, timeoutMs);
    child.on('message', (msg) => {
      if (msg === 'ready') { if (++ready === children.length) for (const c of children) c.send('go'); return; }
      clearTimeout(timer); resolve(msg); child.kill();
    });
    child.on('error', reject);
  })));
}

test('review of finding 1 (high): a lock held by a live process is never broken as stale, the holder re-checks before signing, and release never removes another lock', async () => {
  // (a) Process A holds the order lock across a slow capabilities call. Its owner file is made to look two minutes old
  // while A is still alive; process B retries the same order meanwhile.
  const m = mock(QUARTER);
  m.capabilitiesDelayMs = 6500;
  const signer = countingSigner();
  const client = freshClient(m);
  const home = process.env.XDG_STATE_HOME;
  const started = Date.now();
  const inFlight = client.pay(ORDER, signer, { execute: true });
  await sleep(300);
  const lockDir = `${client.authorizationFile(ORDER)}.lock`;
  const owner = ownerOf(lockDir);
  const old = (Date.now() - 120000) / 1000;
  utimesSync(owner, old, old);
  const retry = race(home, [ORDER], QUARTER);
  await sleep(5700);
  assert.ok(existsSync(owner), 'the live holder keeps its lock');
  assert.ok(statSync(owner).mtimeMs > started, 'the holder refreshes its lock while it works');
  assert.equal(signer.typed.length, 0, 'A is still waiting on capabilities');
  const [first, [b]] = await Promise.all([inFlight, retry]);
  assert.equal(first.status, 'payment_pending');
  assert.equal(signer.typed.length, 2, 'A signs once');
  assert.equal(m.posts.length, 1);
  assert.equal(b.ok, true, JSON.stringify(b));
  assert.equal(b.signed, 0, 'B waited for A and reused the saved authorization');
  assert.deepEqual(b.nonces, [nonceOf(m.posts[0])], 'one Permit2 nonce for the order across both processes');
  assert.deepEqual(ledgerOf(client), { [today()]: QUARTER }, 'one reservation');
  assert.deepEqual(readdirSync(join(home, 'imd-sdk')).filter((f) => f.endsWith('.lock') || f.endsWith('.tmp')), [], 'locks are released');

  // (b) The lock is taken away mid-flow (which the lock no longer allows, but the holder must not rely on that): the
  // holder refuses before reserving or signing, and its release leaves the other process's lock untouched.
  const m2 = mock(QUARTER);
  m2.capabilitiesDelayMs = 800;
  const s2 = countingSigner();
  const c2 = freshClient(m2);
  const p2 = c2.pay(ORDER, s2, { execute: true });
  await sleep(300);
  const lock2 = `${c2.authorizationFile(ORDER)}.lock`;
  rmSync(lock2, { recursive: true, force: true });
  mkdirSync(lock2);
  const foreign = join(lock2, 'owner-99999-0123456789ab');
  writeFileSync(foreign, hostname());
  await rejects(p2, /lost order-[0-9a-f]+\.json\.lock to another imd process; refusing to continue/);
  assert.equal(s2.typed.length, 0, 'nothing signed after losing the lock');
  assert.equal(m2.posts.length, 0);
  assert.equal(ledgerOf(c2), undefined, 'nothing reserved after losing the lock');
  assert.ok(existsSync(foreign), 'release never removes a lock this process does not own');

  // (c) An authorization for the order appears while the holder is working: it is re-read right before signing.
  const m3 = mock(QUARTER);
  m3.capabilitiesDelayMs = 800;
  const s3 = countingSigner();
  const c3 = freshClient(m3);
  const p3 = c3.pay(ORDER, s3, { execute: true });
  await sleep(300);
  writeFileSync(c3.authorizationFile(ORDER), JSON.stringify({ order: ORDER, day: today(), amount: QUARTER, nonce: '7', deadline: String(now() + 50), header: 'eyJ4NDAyVmVyc2lvbiI6Mn0=', quoteSignature: `0x${'ab'.repeat(65)}` }));
  await rejects(p3, /saved while this process was working; refusing to sign a second one/);
  assert.equal(s3.typed.length, 0);
  assert.equal(m3.posts.length, 0);
  assert.equal(ledgerOf(c3), undefined);
});

test('review of finding 2 (medium): breaking a stale ledger lock is atomic: many processes, one stale lock, exactly one authorization', async () => {
  const dead = spawnSync(process.execPath, ['-e', '']).pid;
  const old = (Date.now() - 120000) / 1000;
  const orders = ['order-a', 'order-b', 'order-c', 'order-d', 'order-e', 'order-f'];
  for (let trial = 0; trial < 10; trial++) {
    const home = mkdtempSync(join(ROOT, 'stale-'));
    mkdirSync(join(home, 'imd-sdk'));
    const lock = join(home, 'imd-sdk', 'daily-spend.json.lock');
    if (trial % 2) {
      // A lock left by a crashed process of this version: a directory whose owner pid is dead and whose lease has lapsed.
      mkdirSync(lock);
      writeFileSync(join(lock, `owner-${dead}-0123456789ab`), hostname());
      utimesSync(join(lock, `owner-${dead}-0123456789ab`), old, old);
    } else {
      // A lock file left by the previous version.
      writeFileSync(lock, '99999');
      utimesSync(lock, old, old);
    }
    const results = await race(home, orders, '300000000000000000');
    const ok = results.filter((r) => r.ok);
    assert.equal(ok.length, 1, `trial ${trial}: exactly one process may authorize 0.3 IMD under a 0.5 IMD cap: ${JSON.stringify(results)}`);
    assert.ok(results.filter((r) => !r.ok).every((r) => /daily IMD spending cap exceeded/.test(r.error) && r.signed === 0), JSON.stringify(results));
    assert.deepEqual(JSON.parse(readFileSync(join(home, 'imd-sdk', 'daily-spend.json'), 'utf8')), { [today()]: '300000000000000000' });
    assert.deepEqual(readdirSync(join(home, 'imd-sdk')).filter((f) => f.endsWith('.lock') || f.endsWith('.tmp')), [], 'no lock or temp directory is left behind');
  }
  // A lock with a stale-looking mtime but a live owner pid is not broken: the waiter waits until the owner releases it.
  const home = mkdtempSync(join(ROOT, 'live-'));
  mkdirSync(join(home, 'imd-sdk'));
  const lock = join(home, 'imd-sdk', 'daily-spend.json.lock');
  const live = join(lock, `owner-${process.pid}-0123456789ab`);
  mkdirSync(lock);
  writeFileSync(live, hostname());
  utimesSync(live, old, old);
  let reported;
  const waiting = race(home, ['order-z'], '300000000000000000').then((r) => { reported = r[0]; return r[0]; });
  await sleep(1500);
  assert.ok(existsSync(live), 'a lock whose owner is alive is never broken, however old its mtime');
  assert.equal(reported, undefined, 'the waiter is still waiting');
  rmSync(lock, { recursive: true, force: true });
  const held = await waiting;
  assert.equal(held.ok, true, JSON.stringify(held));
  assert.equal(held.signed, 2);
});

test('review of finding 1 (low): a parseable but incomplete or garbled saved authorization fails closed instead of being replaced', async () => {
  const m = mock(TENTH);
  const signer = countingSigner();
  const client = freshClient(m);
  assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending');
  assert.equal(signer.typed.length, 2);
  const file = client.authorizationFile(ORDER);
  const good = JSON.parse(readFileSync(file, 'utf8'));
  const cases = [
    '{"order":"order-1"}',
    JSON.stringify({ ...good, deadline: 'soon' }),
    JSON.stringify({ ...good, deadline: undefined }),
    JSON.stringify({ ...good, amount: '0.1' }),
    JSON.stringify({ ...good, day: 'today' }),
    JSON.stringify({ ...good, header: '' }),
    JSON.stringify({ ...good, quoteSignature: 12 }),
    JSON.stringify({ ...good, order: 'order-2' }),
    '[]',
    'null',
  ];
  for (const corrupt of cases) {
    m.quoted();
    writeFileSync(file, corrupt);
    await rejects(client.pay(ORDER, signer, { execute: true }), /saved payment authorization corrupt; refusing to sign/);
    assert.equal(signer.typed.length, 2, `${corrupt}: no replacement signed`);
    assert.equal(m.posts.length, 1, `${corrupt}: nothing submitted`);
    assert.equal(ledgerOf(client)[today()], TENTH, `${corrupt}: the reservation is neither released nor doubled`);
    assert.equal(readFileSync(file, 'utf8'), corrupt, `${corrupt}: the record is never overwritten`);
  }
  // The intact record is still reused byte for byte.
  m.quoted();
  writeFileSync(file, JSON.stringify(good));
  assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending');
  assert.equal(signer.typed.length, 2);
  assert.equal(m.posts.length, 2);
  assert.equal(m.posts[1].header, m.posts[0].header);
});

test('review of finding 1 (info): a saved authorization stays live for 30 s past its deadline; a replacement is signed only after that', async () => {
  const m = mock(TENTH);
  const signer = countingSigner();
  const client = freshClient(m);
  await client.pay(ORDER, signer, { execute: true });
  const file = client.authorizationFile(ORDER);
  const good = JSON.parse(readFileSync(file, 'utf8'));
  // Ten seconds past the deadline: clock skew territory, the first authorization may still settle; reuse it.
  m.quoted();
  writeFileSync(file, JSON.stringify({ ...good, deadline: String(now() - 10) }));
  assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending');
  assert.equal(signer.typed.length, 2, 'no replacement inside the grace period');
  assert.equal(m.posts.length, 2);
  assert.equal(nonceOf(m.posts[1]), nonceOf(m.posts[0]));
  assert.equal(ledgerOf(client)[today()], TENTH);
  // Forty seconds past the deadline and still quoted: the old authorization cannot settle, so a replacement is signed.
  m.quoted();
  writeFileSync(file, JSON.stringify({ ...good, deadline: String(now() - 40) }));
  assert.equal((await client.pay(ORDER, signer, { execute: true })).status, 'payment_pending');
  assert.equal(signer.typed.length, 4, 'a replacement after the grace period');
  assert.equal(m.posts.length, 3);
  assert.notEqual(nonceOf(m.posts[2]), nonceOf(m.posts[0]));
  assert.equal(ledgerOf(client)[today()], TENTH, 'the lapsed reservation is released before the replacement is reserved');
});
