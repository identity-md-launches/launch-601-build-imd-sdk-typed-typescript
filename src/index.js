// @ts-check
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { LocalPrivateKeySigner, sha256, toHex } from './crypto.js';

export { LocalPrivateKeySigner } from './crypto.js';
export const API_URL = 'https://api.imd.fun';
export const IMD_TOKEN = '0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7';
export const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
export const X402_PERMIT2_PROXY = '0x402085c248eea27d92e8b30b2c58ed07f9e20001';
const NETWORK = 'eip155:1', SCHEME = 'exact', TRANSFER_METHOD = 'permit2', MAX_TIMEOUT_SECONDS = 86400;
const pending = new Set(['quoted','payment_pending','admission_pending']);
/** Order states in which the service already holds a payment for the order: never sign another one. */
const settled = new Set(['payment_pending','admission_pending','admitted','paid']);
let reservationQueue = Promise.resolve();
const orderQueues = new Map();
const sleep = (ms) => new Promise(r=>setTimeout(r,ms));
/** Canonical JSON (keys sorted, no whitespace). Rejects undefined instead of emitting it (finding 9). */
const canon = (v) => { if(v===undefined)throw new Error('cannot canonicalize undefined'); return v===null?'null':Array.isArray(v)?`[${v.map(canon).join(',')}]`:typeof v==='object'?`{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`:JSON.stringify(v); };
const eqAddress=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
const isAddress=(v)=>typeof v==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v);
const isHash=(v)=>typeof v==='string'&&/^(0x)?[0-9a-fA-F]{64}$/.test(v);
const isAmount=(v)=>typeof v==='string'&&/^[0-9]+$/.test(v);
const b32=(v)=>v.startsWith('0x')?v:`0x${v}`;
const orderId=(o)=>typeof o==='string'?o:o.id;
const nowSeconds=()=>Math.floor(Date.now()/1000);
function paymentOf(v) { return v?.payment || v?.price || v; }
/** Saved quotes arrive flat or nested (quote response, status response, bare quote); normalize before comparing (finding 3). */
function normalizeQuote(v) { const q=v?.quote||v?.order?.quote||(v?.id&&v?.quoteHash?v:undefined);if(!q)return undefined;const p=q.payment||q.price||(q.asset&&q.amount&&q.payTo?{network:q.network,asset:q.asset,amount:q.amount,payTo:q.payTo}:undefined);if(!p)return undefined;return {...q,payment:p}; }
/** Exclusive cross-process lock: O_EXCL lock file, bounded wait, stale locks broken (findings 1, 2). */
async function acquireLock(path,timeoutMs=15000,staleMs=60000) { const start=Date.now();for(;;){try{const fh=await open(path,'wx',0o600);await fh.writeFile(String(process.pid));await fh.close();return ()=>rm(path,{force:true});}catch(e){if(e.code!=='EEXIST')throw e;try{const s=await stat(path);if(Date.now()-s.mtimeMs>staleMs){await rm(path,{force:true});continue;}}catch{}if(Date.now()-start>timeoutMs)throw new Error(`could not acquire ${basename(path)}; another imd process holds it`);await sleep(20+Math.random()*40);}} }
/** Atomic replace: temp file (0600) then rename (finding 2). */
async function writeAtomic(path,text) { const tmp=`${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;await writeFile(tmp,text,{mode:0o600});await rename(tmp,path); }
/** @param {unknown} body @param {number} status */
export class ImdError extends Error { constructor(body,status) { super(body?.detail||body?.error||`IMD request failed (${status})`);this.name='ImdError';this.body=body;this.status=status; } }

/** @typedef {{address:string, signTypedData:(typed:any)=>Promise<string>}} Signer */
/** @typedef {{baseUrl?:string, token?:string, signer?:Signer, maxPerRequest?:string|bigint, maxPerDay?:string|bigint, fetch?:typeof globalThis.fetch}} ImdClientOptions */
export class ImdClient {
  /** @param {ImdClientOptions} [options] */
  constructor(options={}) { this.baseUrl=(options.baseUrl||API_URL).replace(/\/$/,'');this.token=options.token||randomBytes(32).toString('hex');this.signer=options.signer;this.maxPerRequest=BigInt(options.maxPerRequest??'500000000000000000');this.maxPerDay=BigInt(options.maxPerDay??'500000000000000000');this.fetch=options.fetch||globalThis.fetch;this.quotes=new Map();this.inputs=new Map();this.spendFile=join(process.env.XDG_STATE_HOME||join(homedir(),'.local','state'),'imd-sdk','daily-spend.json'); }
  headers(json=false) { return {Authorization:`Bearer ${this.token}`,...(json?{'Content-Type':'application/json'}:{})}; }
  async request(path,init={},allow=[]) { const r=await this.fetch(`${this.baseUrl}${path}`,init);let body=null;const text=await r.text();try{body=text?JSON.parse(text):null;}catch{body=text;}if(!r.ok&&!allow.includes(r.status))throw new ImdError(body,r.status);return {status:r.status,body}; }
  /** Get live action prices, terms and launch chains. */ async capabilities() { return (await this.request('/requests/capabilities',{headers:this.headers()})).body; }
  /** Free evaluator request. Retries transient/noisy evaluator failures up to three times. @param {string} action @param {object} input */
  async check(action,input) { let last;for(let i=0;i<3;i++)try{return (await this.request('/requests/check',{method:'POST',headers:this.headers(true),body:JSON.stringify({action,input})})).body;}catch(e){last=e;if(!(e instanceof ImdError)||![429,500,502,503].includes(e.status)||i===2)throw e;}throw last; }
  /** Resolve a public GitHub repository to its immutable import. `kind` is code, contracts, or site. @param {string} url @param {'code'|'contracts'|'site'} [kind] */ async importRepo(url,kind='code') { return (await this.request('/requests/import',{method:'POST',headers:this.headers(true),body:JSON.stringify({url,kind})})).body; }
  /** Create a paid order but do not sign or submit payment. @param {string} action @param {object} input */
  async quote(action,input) { const out=(await this.request('/requests/quote',{method:'POST',headers:this.headers(true),body:JSON.stringify({requestKey:randomUUID(),action,input})})).body;const id=out?.order?.id;if(id){this.quotes.set(id,out);this.inputs.set(id,input);}return out; }
  /** @param {string|{id:string}} order */ async status(order) { return (await this.request(`/requests/${encodeURIComponent(orderId(order))}`,{headers:this.headers()})).body; }
  /** Poll an order through all paid-request pending states. @param {string|{id:string}} order @param {{intervalMs?:number,timeoutMs?:number}} [options] */
  async waitFor(order,options={}) { const until=Date.now()+(options.timeoutMs??120000);do{const result=await this.status(order);if(!pending.has(result.status))return result;if(Date.now()>=until)throw new Error('timed out waiting for IMD order');await new Promise(r=>setTimeout(r,options.intervalMs??1000));}while(true); }
  /** @param {string} id */ async job(id) { return (await this.request(`/jobs/${encodeURIComponent(id)}`)).body; }
  /** @param {string} id */ async jobReport(id) { return (await this.request(`/jobs/${encodeURIComponent(id)}/report.md`)).body; }
  /** @param {string} owner */ async schedules(owner) { return (await this.request(`/schedules?owner=${encodeURIComponent(owner)}`)).body; }
  async challenge(id) { return this.request(`/requests/${encodeURIComponent(id)}/submit`,{method:'POST',headers:this.headers()},[200,202,402]); }
  /** Validate every signing input before any budget is reserved or anything is signed (findings 3-9). @param {{id?:string,input?:any}} [context] */
  verifyTerms(challenge, quote, capabilities, context={}) {
    const ch=challenge, accepted=ch?.accepts?.[0], q=ch?.quote, qp=paymentOf(q);
    const policy=(capabilities?.actions||capabilities||[]).find?.(x=>x.action===q?.action)||capabilities, cp=paymentOf(policy);
    if(!accepted||!q||!qp||!cp||typeof q.action!=='string')throw new Error('payment terms missing; refusing to sign');
    // Finding 9: the resource is part of the signed payload; a challenge without one is malformed.
    if(!ch.resource||typeof ch.resource!=='object'||typeof ch.resourceUrl!=='string'||!ch.resourceUrl)throw new Error('challenge resource missing; refusing to sign');
    if(ch.resource.url!==undefined&&ch.resource.url!==ch.resourceUrl)throw new Error('challenge resource does not match resourceUrl; refusing to sign');
    if(!isHash(ch.requesterScopeHash))throw new Error('challenge requesterScopeHash missing; refusing to sign');
    // Finding 7: the resource must be the selected order's resource.
    if(context.id!==undefined){let path;try{path=new URL(ch.resourceUrl).pathname;}catch{throw new Error('challenge resourceUrl is not a valid URL; refusing to sign');}if(!path.endsWith(`/requests/${encodeURIComponent(context.id)}`))throw new Error('challenge resource is not the selected order; refusing to sign');}
    // Finding 5: only mainnet exact Permit2 terms, consistently across challenge, quote and capabilities.
    if(accepted.network!==NETWORK||accepted.scheme!==SCHEME||accepted.extra?.assetTransferMethod!==TRANSFER_METHOD)throw new Error(`unsupported payment terms; only ${NETWORK} ${SCHEME} ${TRANSFER_METHOD} is supported; refusing to sign`);
    for(const p of [qp,cp,capabilities?.payment]){if(!p)continue;if((p.network!==undefined&&p.network!==NETWORK)||(p.scheme!==undefined&&p.scheme!==SCHEME)||(p.assetTransferMethod!==undefined&&p.assetTransferMethod!==TRANSFER_METHOD))throw new Error(`payment terms are inconsistent across challenge, quote and capabilities; only ${NETWORK} ${SCHEME} ${TRANSFER_METHOD} is supported; refusing to sign`);}
    // Findings 3 and 7: the saved quote is required, normalized, and bound by id, hash, asset and all priced terms.
    const original=normalizeQuote(quote);
    if(!original)throw new Error('original quote missing; quote the order with this client or read it from status before paying');
    const op=original.payment;
    if(typeof q.id!=='string'||!q.id||!isHash(q.quoteHash)||original.id!==q.id||String(original.quoteHash).toLowerCase()!==String(q.quoteHash).toLowerCase()||original.action!==q.action||String(original.expiresAt)!==String(q.expiresAt)||!eqAddress(op.asset,qp.asset)||!eqAddress(op.payTo,qp.payTo)||String(op.amount)!==String(qp.amount)||(original.runs!==undefined||q.runs!==undefined)&&String(original.runs)!==String(q.runs))throw new Error('challenge quote differs from the original quote');
    const same=(a,b)=>eqAddress(a.asset,b.asset)&&eqAddress(a.payTo,b.payTo);
    if(!same(accepted,qp)||!same(accepted,cp)||!eqAddress(accepted.asset,IMD_TOKEN)||!isAddress(accepted.asset)||!isAddress(accepted.payTo))throw new Error('challenge payment terms differ from quote or capabilities');
    if(!isAmount(accepted.amount)||!isAmount(cp.amount)||String(accepted.amount)!==String(qp.amount))throw new Error('invalid payment amount');
    // Finding 8: per-run actions are priced runs x unitAmount in integer math; runs must match the request.
    let expected;
    if(capabilities?.pricedPer?.[q.action]==='run'){
      const runs=q.runs;
      if(!Number.isInteger(runs)||runs<=0||!isAmount(q.unitAmount))throw new Error('per-run quote is missing a valid run count or unit amount; refusing to sign');
      if(BigInt(q.unitAmount)!==BigInt(cp.amount))throw new Error('per-run unit price differs from capabilities; refusing to sign');
      const requested=context.input?.runs??ch.input?.runs;
      if(requested!==undefined&&String(requested)!==String(runs))throw new Error('quoted run count differs from the request; refusing to sign');
      expected=BigInt(runs)*BigInt(q.unitAmount);
    } else expected=BigInt(cp.amount);
    const amount=BigInt(accepted.amount);
    if(amount!==expected)throw new Error('challenge payment terms differ from quote or capabilities');
    if(amount<=0n||amount>=(1n<<256n))throw new Error('invalid payment amount');if(amount>this.maxPerRequest)throw new Error('per-request IMD spending cap exceeded');
    // Finding 6: deadline = min(quote.expiresAt - 5, now + maxTimeoutSeconds) with a positive bounded timeout.
    const timeout=accepted.maxTimeoutSeconds;
    if(!Number.isInteger(timeout)||timeout<=0||timeout>MAX_TIMEOUT_SECONDS)throw new Error('invalid payment timeout; refusing to sign');
    if(!Number.isInteger(q.expiresAt)||q.expiresAt<=0)throw new Error('invalid quote expiry; refusing to sign');
    const now=BigInt(nowSeconds()), expiry=BigInt(q.expiresAt), deadline=expiry-5n<now+BigInt(timeout)?expiry-5n:now+BigInt(timeout);
    if(deadline<=now)throw new Error('quote expires too soon to sign safely');
    const key=new Date().toISOString().slice(0,10);
    return {accepted,q,original,amount,key,deadline};
  }
  /** Spend ledger: fail closed on anything but a missing file (finding 2). */
  async readLedger() { let text;try{text=await readFile(this.spendFile,'utf8');}catch(e){if(e?.code==='ENOENT')return {};throw new Error('spend ledger unreadable; refusing to sign');}let ledger;try{ledger=JSON.parse(text);}catch{throw new Error('spend ledger corrupt; refusing to sign');}if(!ledger||typeof ledger!=='object'||Array.isArray(ledger)||!Object.values(ledger).every(isAmount))throw new Error('spend ledger corrupt; refusing to sign');return ledger; }
  /** Read-check-write of the ledger under an in-process mutex and an exclusive lock file; `delta` < 0 releases (findings 2, 4). @param {string} day @param {bigint} delta */
  async adjustSpend(day,delta) {
    let release;const previous=reservationQueue;reservationQueue=new Promise(resolve=>{release=resolve;});await previous;
    try{await mkdir(dirname(this.spendFile),{recursive:true,mode:0o700});const unlock=await acquireLock(`${this.spendFile}.lock`);
      try{const ledger=await this.readLedger();const spent=BigInt(ledger[day]||0);if(delta>0n&&spent+delta>this.maxPerDay)throw new Error('daily IMD spending cap exceeded');const next=spent+delta<0n?0n:spent+delta;ledger[day]=next.toString();await writeAtomic(this.spendFile,JSON.stringify(ledger));}
      finally{await unlock();}}
    finally{release();}
  }
  authorizationFile(id) { return join(dirname(this.spendFile),`order-${createHash('sha256').update(String(id)).digest('hex').slice(0,32)}.json`); }
  /** @param {string} id */ async readAuthorization(id) { try{const saved=JSON.parse(await readFile(this.authorizationFile(id),'utf8'));return saved&&saved.order===id&&typeof saved.header==='string'&&typeof saved.quoteSignature==='string'?saved:undefined;}catch(e){if(e?.code==='ENOENT')return undefined;throw new Error('saved payment authorization unreadable; refusing to sign');} }
  async submitSigned(id,saved) { return this.request(`/requests/${encodeURIComponent(id)}/submit`,{method:'POST',headers:{...this.headers(true),'PAYMENT-SIGNATURE':saved.header},body:JSON.stringify({quoteSignature:saved.quoteSignature})},[200,202]); }
  /** Challenge, validate and (only with execute:true) sign and submit a payment. A viem account is accepted directly as signer. @param {string|{id:string}} order @param {Signer} [signer] @param {{execute?:boolean}} [options] */
  async pay(order,signer=this.signer,options={}) {
    const id=orderId(order);const first=await this.challenge(id);if(first.status!==402)return first.body;
    if(!options.execute)return {dryRun:true,order:{id},message:'Payment not signed. Pass execute:true to sign and submit.'};
    if(!signer)throw new Error('a viem-compatible signer is required for execute:true');
    // Finding 1: one payment flow per order at a time, in this process and across processes.
    const previous=orderQueues.get(id)||Promise.resolve();let done;const mine=new Promise(resolve=>{done=resolve;});const chained=previous.then(()=>mine);orderQueues.set(id,chained);await previous;
    try{await mkdir(dirname(this.spendFile),{recursive:true,mode:0o700});const unlock=await acquireLock(`${this.authorizationFile(id)}.lock`);try{return await this.execute(id,first.body,signer);}finally{await unlock();}}
    finally{done();if(orderQueues.get(id)===chained)orderQueues.delete(id);}
  }
  /** @param {string} id @param {Signer} signer */
  async execute(id,ch,signer) {
    const saved=await this.readAuthorization(id);
    // Finding 1: reconcile with GET /requests/{id} before reusing or ever replacing an authorization.
    const current=await this.status(id);
    if(settled.has(current?.status))return current;
    if(saved){
      if(nowSeconds()<Number(saved.deadline)){
        if(current?.status==='payment_failed')throw new Error(`a previous payment authorization for this order is valid until ${saved.deadline}; refusing to sign a second one before it expires`);
        return (await this.submitSigned(id,saved)).body;
      }
      // The saved Permit2 deadline has passed: it can no longer settle, so its reservation is released and a replacement may be signed.
      await this.adjustSpend(saved.day,-BigInt(saved.amount));await rm(this.authorizationFile(id),{force:true});
    }
    if(typeof signer.signTypedData!=='function'||!isAddress(signer.address))throw new Error('signer must expose an address and signTypedData; refusing to sign');
    const terms=this.verifyTerms(ch,this.quotes.get(id)||current,await this.capabilities(),{id,input:this.inputs.get(id)});
    const deadline=terms.deadline, nonce=BigInt(`0x${randomBytes(32).toString('hex')}`);
    const authorization={from:signer.address,permitted:{token:terms.accepted.asset,amount:String(terms.amount)},spender:X402_PERMIT2_PROXY,nonce:String(nonce),deadline:String(deadline),witness:{to:terms.accepted.payTo,validAfter:'0'}};
    const permit={domain:{name:'Permit2',chainId:1,verifyingContract:PERMIT2},primaryType:'PermitWitnessTransferFrom',types:{PermitWitnessTransferFrom:[{name:'permitted',type:'TokenPermissions'},{name:'spender',type:'address'},{name:'nonce',type:'uint256'},{name:'deadline',type:'uint256'},{name:'witness',type:'Witness'}],TokenPermissions:[{name:'token',type:'address'},{name:'amount',type:'uint256'}],Witness:[{name:'to',type:'address'},{name:'validAfter',type:'uint256'}]},message:{permitted:{token:terms.accepted.asset,amount:terms.amount},spender:X402_PERMIT2_PROXY,nonce,deadline,witness:{to:terms.accepted.payTo,validAfter:0n}}};
    const paymentFor=(signature)=>({x402Version:2,resource:ch.resource,accepted:terms.accepted,payload:{signature,permit2Authorization:authorization}});
    canon(paymentFor('0x'));
    // Finding 4: budget is reserved only after every signing input is valid.
    await this.adjustSpend(terms.key,terms.amount);
    let signature,quoteSignature,payment,header;
    try{
      signature=await signer.signTypedData(permit);payment=paymentFor(signature);header=Buffer.from(canon(payment)).toString('base64');
      const o=terms.original, op=o.payment;
      const approval={domain:{name:'IdentityMD Paid Action',version:'1',chainId:1},primaryType:'QuoteApproval',types:{QuoteApproval:[{name:'resource',type:'string'},{name:'requesterScopeHash',type:'bytes32'},{name:'quoteId',type:'string'},{name:'quoteHash',type:'bytes32'},{name:'paymentHash',type:'bytes32'},{name:'action',type:'string'},{name:'asset',type:'address'},{name:'amount',type:'uint256'},{name:'payTo',type:'address'},{name:'expiresAt',type:'uint256'}]},message:{resource:ch.resourceUrl,requesterScopeHash:b32(ch.requesterScopeHash),quoteId:o.id,quoteHash:b32(o.quoteHash),paymentHash:toHex(sha256(canon(payment))),action:o.action,asset:op.asset,amount:BigInt(op.amount),payTo:op.payTo,expiresAt:BigInt(o.expiresAt)}};
      quoteSignature=await signer.signTypedData(approval);
      if(BigInt(nowSeconds())>=deadline)throw new Error('quote expires too soon to sign safely');
      // Finding 1: persist the exact payload before it leaves the process so a retry reuses it.
      await writeAtomic(this.authorizationFile(id),JSON.stringify({order:id,day:terms.key,amount:String(terms.amount),nonce:String(nonce),deadline:String(deadline),quoteId:o.id,quoteHash:String(o.quoteHash),signer:signer.address,header,quoteSignature,createdAt:nowSeconds()}));
    }catch(error){await this.adjustSpend(terms.key,-terms.amount).catch(()=>{});throw error;}
    // From here the authorization may have reached the service: the reservation stays until reconciled.
    const response=await this.submitSigned(id,{header,quoteSignature});return response.body;
  }
}
/** Create an IMD client. @param {ImdClientOptions} [options] */
export function createClient(options={}) { return new ImdClient(options); }
