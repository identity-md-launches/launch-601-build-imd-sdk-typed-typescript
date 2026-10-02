import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { ImdClient, LocalPrivateKeySigner } from '../src/index.js';

const KEY='0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412c8b4f11f99f37b';
const ASSET='0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7';
const PAY_TO='0x4e0fa57bde726079356537e2f34d671e9f41adbc';
const AMOUNT='500000000000000000';
const permit={domain:{name:'Permit2',chainId:1,verifyingContract:'0x000000000022D473030F116dDEE9F6B43aC78BA3'},primaryType:'PermitWitnessTransferFrom',types:{PermitWitnessTransferFrom:[{name:'permitted',type:'TokenPermissions'},{name:'spender',type:'address'},{name:'nonce',type:'uint256'},{name:'deadline',type:'uint256'},{name:'witness',type:'Witness'}],TokenPermissions:[{name:'token',type:'address'},{name:'amount',type:'uint256'}],Witness:[{name:'to',type:'address'},{name:'validAfter',type:'uint256'}]},message:{permitted:{token:ASSET,amount:500000000000000000n},spender:'0x402085c248EeA27D92E8b30b2C58ed07f9E20001',nonce:42n,deadline:1800000000n,witness:{to:PAY_TO,validAfter:0n}}};
const approval={domain:{name:'IdentityMD Paid Action',version:'1',chainId:1},primaryType:'QuoteApproval',types:{QuoteApproval:[{name:'resource',type:'string'},{name:'requesterScopeHash',type:'bytes32'},{name:'quoteId',type:'string'},{name:'quoteHash',type:'bytes32'},{name:'paymentHash',type:'bytes32'},{name:'action',type:'string'},{name:'asset',type:'address'},{name:'amount',type:'uint256'},{name:'payTo',type:'address'},{name:'expiresAt',type:'uint256'}]},message:{resource:'https://api.example/requests/order-1',requesterScopeHash:`0x${'11'.repeat(32)}`,quoteId:'quote-1',quoteHash:`0x${'22'.repeat(32)}`,paymentHash:`0x${'33'.repeat(32)}`,action:'job.open',asset:ASSET,amount:500000000000000000n,payTo:PAY_TO,expiresAt:1800000100n}};

test('fixed EIP-712 Permit2 and QuoteApproval vectors match independently generated viem signatures', async () => {
  // These fixed vectors were independently generated with viem privateKeyToAccount
  // from this known key and challenge, rather than derived from the SDK at test time.
  const signer=new LocalPrivateKeySigner(KEY);
  assert.equal(signer.address,'0x0f740eec79b13a840ac194a801aa5d55741f873b');
  assert.equal(await signer.signTypedData(permit),'0xa8907e60b697953cff765db4b18e12dbb1e740d9292422423160d8d10ea6541643e1dd028ebec7e76ef4da69c2cf9781bff323cac998925413b764dd1d4e15b91c');
  assert.equal(await signer.signTypedData(approval),'0x9bd9e8e23679fdae27d63aedba9fbe456ed7908028702fc3d2866e941e4414bb6be709535a492e37843c6dd35a510731c9146352918f91a353c26b593a433b6c1c');
});

async function mock() {
  let submitted, polls=0, challenges=0;
  const quote={id:'quote-1',quoteHash:'22'.repeat(32),action:'job.open',payment:{asset:ASSET,amount:AMOUNT,payTo:PAY_TO},expiresAt:1800000100};
  const challenge={accepts:[{scheme:'exact',network:'eip155:1',asset:ASSET,amount:AMOUNT,payTo:PAY_TO,maxTimeoutSeconds:60,extra:{assetTransferMethod:'permit2'}}],quote,resource:{url:'https://api.example/requests/order-1',description:'job',mimeType:'application/json'},resourceUrl:'https://api.example/requests/order-1',requesterScopeHash:'11'.repeat(32)};
  const server=createServer(async(req,res)=>{
    const send=(status,value)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));};
    assert.match(req.headers.authorization||'',/^Bearer [0-9a-f]{64}$/);
    let raw='';for await(const part of req)raw+=part;
    if(req.method==='POST'&&req.url==='/requests/quote'){const v=JSON.parse(raw);assert.equal(v.action,'job.open');assert.match(v.requestKey,/^[0-9a-f-]{36}$/);return send(200,{order:{id:'order-1'}});}
    if(req.method==='GET'&&req.url==='/requests/capabilities')return send(200,{actions:[{action:'job.open',payment:quote.payment}]});
    if(req.method==='POST'&&req.url==='/requests/order-1/submit'&&!raw){challenges++;return send(402,challenge);}
    if(req.method==='POST'&&req.url==='/requests/order-1/submit'){
      const payment=JSON.parse(Buffer.from(req.headers['payment-signature'],'base64').toString());
      assert.deepEqual(Object.keys(payment).sort(),['accepted','payload','resource','x402Version']);
      assert.deepEqual(payment.accepted,challenge.accepts[0]);
      assert.equal(payment.payload.permit2Authorization.permitted.token,ASSET);assert.equal(payment.payload.permit2Authorization.permitted.amount,AMOUNT);
      assert.match(payment.payload.signature,/^0x[0-9a-f]{130}$/);assert.match(JSON.parse(raw).quoteSignature,/^0x[0-9a-f]{130}$/);
      submitted={payment,quoteSignature:JSON.parse(raw).quoteSignature};return send(202,{status:'payment_pending',order:{id:'order-1'}});
    }
    if(req.method==='GET'&&req.url==='/requests/order-1'){polls++;return send(200,polls===1?{status:'payment_pending'}:{status:'admitted',admission:{result:{jobId:'job-1'}}});}
    return send(404,{error:'not_found'});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  return {url:`http://127.0.0.1:${port}`,state:()=>({submitted,polls,challenges}),close:()=>new Promise(resolve=>server.close(resolve))};
}

test('quote, 402, both signatures, submit and polling run against a local mock only', async () => {
  const m=await mock();try{
    const real=new LocalPrivateKeySigner(KEY);let signed=0;
    const signer={address:real.address,signTypedData:async data=>{signed++;return real.signTypedData(data);}};
    const client=new ImdClient({baseUrl:m.url,signer});
    const order=await client.quote('job.open',{objective:'test'});assert.equal(order.order.id,'order-1');
    const dry=await client.pay(order.order);assert.equal(dry.dryRun,true);assert.equal(signed,0,'dry run must never sign');
    const paid=await client.pay(order.order,signer,{execute:true});assert.equal(paid.status,'payment_pending');assert.equal(signed,2);
    const outcome=await client.waitFor(order.order,{intervalMs:1,timeoutMs:1000});assert.equal(outcome.status,'admitted');
    const state=m.state();assert.ok(state.submitted);assert.equal(state.challenges,2);assert.equal(state.polls,2);
  } finally { await m.close(); }
});
