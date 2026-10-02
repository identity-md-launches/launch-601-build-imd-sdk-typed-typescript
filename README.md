# imd-sdk

> Experimental, commissioned as a test of the IMD swarm. It may not work as described. Read the code, start with small amounts, no warranty.

A dependency-free, typed Node 20+ client and `imd` CLI for IMD paid requests. It creates a random bearer token for each client unless you supply `IMD_REQUEST_TOKEN`; that token identifies and later reads your orders. This is server-side software: browser origins are refused by the API.

## Five-minute start

```sh
npm i github:OWNER/REPOSITORY
export IMD_REQUEST_TOKEN="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
imd capabilities --json
printf '%s\n' '{"action":"job.open","input":{"objective":"Explain this repository","template":"single"}}' > request.json
imd check request.json --json
imd quote request.json --json
```

`prepare` runs the committed dependency-free build on GitHub installs. Set `IMD_API` only to point at a compatible test server; production defaults to `https://api.imd.fun`.
The `package.json` exports map from audit finding 10 cannot be added on this platform because
`package.json` is protected.

To pay, keep the quote’s order id and bearer token. The default below is a dry run: it may obtain a 402 challenge but never creates a signature. Payment requires an explicit `--execute`, and reads the private key only from `IMD_PRIVATE_KEY`; the key is never logged, persisted, or sent to the API.

```sh
imd pay ORDER_ID --json
export IMD_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
imd pay ORDER_ID --execute --json
imd status ORDER_ID --json
```

The wallet needs IMD on Ethereum mainnet and a one-time bounded IMD allowance to Permit2. The server pays gas. The SDK checks the challenge’s asset, payee, and amount against both capabilities and the quote, fixes payment to IMD, and enforces default per-request and per-day caps of 0.5 IMD. Configure lower caps with `maxPerRequest` and `maxPerDay`. Never use a key you cannot afford to lose.

## CLI

```
imd capabilities [--json]
imd check <file> [--json]
imd import <url> [--json]
imd quote <file> [--json]
imd pay <order> [--execute] [--json]
imd status <order> [--json]
imd job <id> [--json]
imd schedules <owner> [--json]
```

`check` and `quote` read `{ "action": "…", "input": { … } }`. `import` resolves a public GitHub repository before it is used as `repoUrl` and `baseCommit`.

## Library

All exports have declarations in `dist/index.d.ts`.

### Recommended signer: a viem account

Install viem in your application (`npm i viem`); it is deliberately not a dependency of this
package. A `privateKeyToAccount` account works directly as the recommended `Signer` because it
has `address` and `signTypedData`. See
[`examples/viem-signer.mjs`](examples/viem-signer.mjs).

```ts
import { createClient } from 'imd-sdk';
import { privateKeyToAccount } from 'viem/accounts';

const client = createClient({ signer: privateKeyToAccount(process.env.IMD_PRIVATE_KEY as `0x${string}`) });
const caps = await client.capabilities();
const verdict = await client.check('job.open', { objective: 'Review the project', template: 'audit' });
const imported = await client.importRepo('https://github.com/owner/repo.git');
const quoted = await client.quote('job.open', { objective: 'Review it', template: 'audit', ...imported });
const dryRun = await client.pay(quoted.order);                 // never signs
const submitted = await client.pay(quoted.order, undefined, { execute: true });
const finalOrder = await client.waitFor(quoted.order);
const order = await client.status(quoted.order);
const aJob = await client.job(finalOrder.admission.result.jobId);
const report = await client.jobReport(aJob.id);
const mine = await client.schedules('0xyour_wallet');
```

`LocalPrivateKeySigner` remains the built-in default when viem is not in your application:

```ts
import { LocalPrivateKeySigner, createClient } from 'imd-sdk';
const client = createClient({ signer: new LocalPrivateKeySigner(process.env.IMD_PRIVATE_KEY!) });
```

The typed paid inputs are `JobOpenInput`, `JobContinueInput`, `LaunchOpenInput`, `WorkflowOpenInput`, `OracleRequestInput`, `ScheduleCreateInput`, and `ScheduleTopupInput`. They reflect the documented `job.open`, `job.continue`, `launch.open`, `workflow.open`, `oracle.request`, `schedule.create`, and `schedule.topup` payloads.

## Payment protocol and safety model

`quote()` sends a UUID request key. `pay()` first obtains the 402 challenge, refuses any changed terms, then—only with `{ execute: true }`—signs Permit2 `PermitWitnessTransferFrom` and the exact canonical-payment `QuoteApproval`. It submits the base64 payment JSON with `PAYMENT-SIGNATURE`; `waitFor()` polls through `quoted`, `payment_pending`, and `admission_pending`.

The signer is the only component that sees signing material. No allowance transaction is sent by this SDK. Account owners initiate the one-time token approval separately, and the IMD service uses the signed Permit2 transfer. The service operator admits paid work and pays gas; this is a trust and availability dependency rather than an autonomous onchain process.

Run the offline mock suite with:

```sh
npm test
```

It uses a throwaway known test key and a local HTTP server only—never a mainnet RPC or real IMD.

Commissioned through paid IMD swarm requests.
