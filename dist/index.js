// @ts-check
import { randomBytes, randomUUID } from 'node:crypto';
import { LocalPrivateKeySigner, sha256, toHex } from './crypto.js';

export { LocalPrivateKeySigner } from './crypto.js';
export const API_URL = 'https://api.imd.fun';
export const IMD_TOKEN = '0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7';
export const PERMIT2 = '0x000000000022d473030f116dee9f6b43ac78ba3';
export const X402_PERMIT2_PROXY = '0x402085c248eea27d92e8b30b2c58ed07f9e20001';
const pending = new Set(['quoted','payment_pending','admission_pending']);
const daily = new Map();
const canon = (v) => v===null?'null':Array.isArray(v)?`[${v.map(canon).join(',')}]`:typeof v==='object'?`{${Object.keys(v).sort().map(k=>`${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`:JSON.stringify(v);
const eqAddress=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
const b32=(v)=>v.startsWith('0x')?v:`0x${v}`;
const orderId=(o)=>typeof o==='string'?o:o.id;
function paymentOf(v) { return v?.payment || v?.price || v; }
/** @param {unknown} body @param {number} status */
export class ImdError extends Error { constructor(body,status) { super(body?.detail||body?.error||`IMD request failed (${status})`);this.name='ImdError';this.body=body;this.status=status; } }

/** @typedef {{address:string, signTypedData:(typed:any)=>Promise<string>}} Signer */
/** @typedef {{baseUrl?:string, token?:string, signer?:Signer, maxPerRequest?:string|bigint, maxPerDay?:string|bigint, fetch?:typeof globalThis.fetch}} ImdClientOptions */
export class ImdClient {
  /** @param {ImdClientOptions} [options] */
  constructor(options={}) { this.baseUrl=(options.baseUrl||API_URL).replace(/\/$/,'');this.token=options.token||randomBytes(32).toString('hex');this.signer=options.signer;this.maxPerRequest=BigInt(options.maxPerRequest??'500000000000000000');this.maxPerDay=BigInt(options.maxPerDay??'500000000000000000');this.fetch=options.fetch||globalThis.fetch;this.quotes=new Map(); }
  headers(json=false) { return {Authorization:`Bearer ${this.token}`,...(json?{'Content-Type':'application/json'}:{})}; }
  async request(path,init={},allow=[]) { const r=await this.fetch(`${this.baseUrl}${path}`,init);let body=null;const text=await r.text();try{body=text?JSON.parse(text):null;}catch{body=text;}if(!r.ok&&!allow.includes(r.status))throw new ImdError(body,r.status);return {status:r.status,body}; }
  /** Get live action prices, terms and launch chains. */ async capabilities() { return (await this.request('/requests/capabilities',{headers:this.headers()})).body; }
  /** Free evaluator request. Retries transient/noisy evaluator failures up to three times. @param {string} action @param {object} input */
  async check(action,input) { let last;for(let i=0;i<3;i++)try{return (await this.request('/requests/check',{method:'POST',headers:this.headers(true),body:JSON.stringify({action,input})})).body;}catch(e){last=e;if(!(e instanceof ImdError)||![429,500,502,503].includes(e.status)||i===2)throw e;}throw last; }
  /** Resolve a public GitHub repository to its immutable import. `kind` is code, contracts, or site. @param {string} url @param {'code'|'contracts'|'site'} [kind] */ async importRepo(url,kind='code') { return (await this.request('/requests/import',{method:'POST',headers:this.headers(true),body:JSON.stringify({url,kind})})).body; }
  /** Create a paid order but do not sign or submit payment. @param {string} action @param {object} input */
  async quote(action,input) { const out=(await this.request('/requests/quote',{method:'POST',headers:this.headers(true),body:JSON.stringify({requestKey:randomUUID(),action,input})})).body;const id=out?.order?.id;if(id)this.quotes.set(id,out);return out; }
  /** @param {string|{id:string}} order */ async status(order) { return (await this.request(`/requests/${encodeURIComponent(orderId(order))}`,{headers:this.headers()})).body; }
  /** Poll an order through all paid-request pending states. @param {string|{id:string}} order @param {{intervalMs?:number,timeoutMs?:number}} [options] */
  async waitFor(order,options={}) { const until=Date.now()+(options.timeoutMs??120000);do{const result=await this.status(order);if(!pending.has(result.status))return result;if(Date.now()>=until)throw new Error('timed out waiting for IMD order');await new Promise(r=>setTimeout(r,options.intervalMs??1000));}while(true); }
  /** @param {string} id */ async job(id) { return (await this.request(`/jobs/${encodeURIComponent(id)}`)).body; }
  /** @param {string} id */ async jobReport(id) { return (await this.request(`/jobs/${encodeURIComponent(id)}/report.md`)).body; }
  /** @param {string} owner */ async schedules(owner) { return (await this.request(`/schedules?owner=${encodeURIComponent(owner)}`)).body; }
  async challenge(id) { return this.request(`/requests/${encodeURIComponent(id)}/submit`,{method:'POST',headers:this.headers()},[200,202,402]); }
  verifyTerms(challenge, quote, capabilities) {
    const accepted=challenge?.accepts?.[0], q=challenge?.quote, qp=paymentOf(q), cp=paymentOf((capabilities?.actions||capabilities||[]).find?.(x=>x.action===q?.action)||capabilities);
    if(!accepted||!q||!qp||!cp)throw new Error('payment terms missing; refusing to sign');
    const same=(a,b)=>eqAddress(a.asset,b.asset)&&eqAddress(a.payTo,b.payTo)&&String(a.amount)===String(b.amount);
    const originallyQuoted=quote?.quote||quote?.order?.quote;
    if(originallyQuoted?.payment&&(!same(qp,paymentOf(originallyQuoted))||originallyQuoted.action!==q.action||String(originallyQuoted.expiresAt)!==String(q.expiresAt)))throw new Error('challenge quote differs from the original quote');
    if(!same(accepted,qp)||!same(accepted,cp)||!eqAddress(accepted.asset,IMD_TOKEN))throw new Error('challenge payment terms differ from quote or capabilities');
    const amount=BigInt(accepted.amount);if(amount>this.maxPerRequest)throw new Error('per-request IMD spending cap exceeded');
    const key=new Date().toISOString().slice(0,10), spent=daily.get(key)||0n;if(spent+amount>this.maxPerDay)throw new Error('daily IMD spending cap exceeded');
    return {accepted,q,amount,key};
  }
  /** Challenge, validate and (only with execute:true) sign and submit a payment. A viem account is accepted directly as signer. @param {string|{id:string}} order @param {Signer} [signer] @param {{execute?:boolean}} [options] */
  async pay(order,signer=this.signer,options={}) {
    const id=orderId(order);const first=await this.challenge(id);if(first.status!==402)return first.body;
    if(!options.execute)return {dryRun:true,order:{id},message:'Payment not signed. Pass execute:true to sign and submit.'};
    if(!signer)throw new Error('a viem-compatible signer is required for execute:true');
    const terms=this.verifyTerms(first.body,this.quotes.get(id)||await this.status(id),await this.capabilities());const ch=first.body;
    const expiry=BigInt(terms.q.expiresAt), now=BigInt(Math.floor(Date.now()/1000)), deadline=expiry-5n;if(deadline<=now)throw new Error('quote expires too soon to sign safely');
    const nonce=BigInt(`0x${randomBytes(32).toString('hex')}`);
    const authorization={from:signer.address,permitted:{token:terms.accepted.asset,amount:String(terms.amount)},spender:X402_PERMIT2_PROXY,nonce:String(nonce),deadline:String(deadline),witness:{to:terms.accepted.payTo,validAfter:'0'}};
    const permit={domain:{name:'Permit2',chainId:1,verifyingContract:PERMIT2},primaryType:'PermitWitnessTransferFrom',types:{PermitWitnessTransferFrom:[{name:'permitted',type:'TokenPermissions'},{name:'spender',type:'address'},{name:'nonce',type:'uint256'},{name:'deadline',type:'uint256'},{name:'witness',type:'Witness'}],TokenPermissions:[{name:'token',type:'address'},{name:'amount',type:'uint256'}],Witness:[{name:'to',type:'address'},{name:'validAfter',type:'uint256'}]},message:{permitted:{token:terms.accepted.asset,amount:terms.amount},spender:X402_PERMIT2_PROXY,nonce,deadline,witness:{to:terms.accepted.payTo,validAfter:0n}}};
    const signature=await signer.signTypedData(permit);const payment={x402Version:2,resource:ch.resource,accepted:terms.accepted,payload:{signature,permit2Authorization:authorization}};
    const approval={domain:{name:'IdentityMD Paid Action',version:'1',chainId:1},primaryType:'QuoteApproval',types:{QuoteApproval:[{name:'resource',type:'string'},{name:'requesterScopeHash',type:'bytes32'},{name:'quoteId',type:'string'},{name:'quoteHash',type:'bytes32'},{name:'paymentHash',type:'bytes32'},{name:'action',type:'string'},{name:'asset',type:'address'},{name:'amount',type:'uint256'},{name:'payTo',type:'address'},{name:'expiresAt',type:'uint256'}]},message:{resource:ch.resourceUrl,requesterScopeHash:b32(ch.requesterScopeHash),quoteId:terms.q.id,quoteHash:b32(terms.q.quoteHash),paymentHash:toHex(sha256(canon(payment))),action:terms.q.action,asset:terms.q.payment.asset,amount:BigInt(terms.q.payment.amount),payTo:terms.q.payment.payTo,expiresAt:BigInt(terms.q.expiresAt)}};
    const quoteSignature=await signer.signTypedData(approval);const response=await this.request(`/requests/${encodeURIComponent(id)}/submit`,{method:'POST',headers:{...this.headers(true),'PAYMENT-SIGNATURE':Buffer.from(canon(payment)).toString('base64')},body:JSON.stringify({quoteSignature})},[200,202]);daily.set(terms.key,(daily.get(terms.key)||0n)+terms.amount);return response.body;
  }
}
/** Create an IMD client. @param {ImdClientOptions} [options] */
export function createClient(options={}) { return new ImdClient(options); }
