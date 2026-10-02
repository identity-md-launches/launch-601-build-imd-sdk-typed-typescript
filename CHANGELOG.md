# Changelog

> Experimental, commissioned as a test of the IMD swarm. It may not work as described. Read the code, start with small amounts, no warranty.

## Unreleased — dry-run example and schedule.create check type

1. **Safety — the viem example paid when run as written.** `examples/viem-signer.mjs` called
   `pay(..., { execute: true })`. It now passes `execute` only when `IMD_EXECUTE=1` is set in the
   environment, prints a warning naming the order before paying, and otherwise performs the dry
   run. The README signer section says so. No payment, retry or cap behaviour changed.
2. **Types — `CheckResult` did not match a live `schedule.create` check.** The live
   `POST /requests/check` response for `schedule.create` has no `kind`, `plan`, `facts` or `judged`
   and returns `unitAmount`, `runs`, `amount` and `terms` instead. In `src/index.d.ts` (and
   `dist/`) `CheckResult.kind`, `plan`, `facts` and `judged` are now optional, and optional
   `unitAmount: string`, `runs: number`, `amount: string` and `terms: string` were added. The
   live body (7 runs, captured 2026-10-02 from https://api.imd.fun) is saved as
   `test/fixtures/live/check-schedule-create.json` and checked by the drift test.

## Unreleased — typed live responses and signer documentation

- Replaced every `Promise<any>` client result with exported API response interfaces, including
  `Capabilities`, `CheckResult`, `Order`, `OrderStatus`, `Challenge`, `Job`, and `Schedule`.
  Saved live OpenAPI, capabilities, check, import, job, and schedules responses now back a drift
  test for every required declared response field.
- Added `examples/viem-signer.mjs` and README guidance that a user-installed viem
  `privateKeyToAccount` is the recommended signer. `LocalPrivateKeySigner` remains the built-in
  default.
- Reformatted `src/index.js`, `src/crypto.js`, and `src/cli.js` for readability without changing
  behavior; source lines are kept at 120 characters or fewer.
- The `package.json` exports map requested by audit finding 10 still cannot be added because
  `package.json` is protected on this platform.

## 0.1.1 (unreleased) — fixes for the audit of 91407cb

Audit: https://api.imd.fun/jobs/ae3c9745-7363-4bd2-bfaf-dc8944649cd8/report.md. Each finding has a regression test in `test/audit-findings.test.mjs` that fails on 91407cb and passes now. `dist/` is a fresh copy of `src/`. The public API, the CLI commands, the dry-run default and the 0.5 IMD per-request and per-day caps are unchanged.

1. **High — a retry could sign a second Permit2 authorization.** `pay()` now serializes per order (in-process queue plus an exclusive `order-<hash>.json.lock` file), reads `GET /requests/{id}` before signing anything, returns the order when the service already holds a payment (`payment_pending`, `admission_pending`, `admitted`, `paid`), and persists the exact signed payload (`PAYMENT-SIGNATURE` header and `quoteSignature`) to a 0600 `order-<hash>.json` next to the spend ledger before it is sent. A retry resubmits that payload byte for byte; a replacement is signed only after the saved Permit2 deadline has passed, when the old authorization can no longer settle.
2. **High — the daily cap did not hold across processes.** The ledger read-check-write now runs under an exclusive lock file (`daily-spend.json.lock`, O_EXCL, bounded wait, stale locks broken) and writes through a 0600 temp file plus rename. A missing ledger is empty; an unreadable, truncated or malformed one fails closed with `spend ledger corrupt; refusing to sign` and is never overwritten.
3. **Medium — unchanged nested quotes were rejected.** Saved quotes are normalized (quote response `order.quote`, status response `order.quote`, `{ order, quote }`, bare quote, flat or nested `payment`) before comparison, so an unchanged quote passes.
4. **Medium — failures before authorization consumed the daily budget.** Every signing input (expiry, terms, resource, timeout, signer address) is validated and the typed data is built before any budget is reserved. A signer failure or any other failure before the payload leaves the process releases the reservation; a submitted attempt with an ambiguous or rejected outcome stays reserved until reconciled.
5. **Medium — unsupported networks and schemes received mainnet Permit2 signatures.** The challenge must be `eip155:1`, scheme `exact`, `assetTransferMethod` `permit2`, and the quote payment and capabilities must agree wherever they carry those fields. Anything else is refused before reserving or signing.
6. **Medium — Permit2 deadline exceeded the advertised timeout.** `deadline = min(quote.expiresAt - 5, now + accepted.maxTimeoutSeconds)`; the timeout must be a positive integer of at most 86400 seconds, and freshness is rechecked right before the payment is sent.
7. **Medium — QuoteApproval was not bound to the saved quote.** The challenge quote must match the saved quote's id, quoteHash, action, asset, payTo, amount, expiresAt and runs; the approval message is built from the saved quote; the challenge resource must be `.../requests/<order id>` of the selected order and `resource.url` must equal `resourceUrl`. A missing original quote fails closed.
8. **Medium — per-run schedule prices were compared as a single-run total.** For actions listed as `run` in capabilities `pricedPer` (`schedule.create`, `schedule.topup`) the expected total is `runs × unitAmount` in BigInt arithmetic, `unitAmount` must equal the capabilities price, `runs` must match the request (the saved quote, the client's own input and the challenge `input`), and both caps apply to the total.
9. **Low — a missing resource produced an invalid payment header.** A challenge without `resource`, `resourceUrl` or `requesterScopeHash` is refused before reserving or signing, and canonical JSON throws on `undefined` instead of emitting it.
10. **Low — deep-imported helpers leaked malformed keys in errors.** `signDigest` and `addressFromPrivateKey` validate and normalize the key (`0x`-optional 64 hex, `0 < d < N`) and throw the static `invalid private key`, never a message containing key material. The requested `package.json` exports map is **not** included: this revision's rules forbid changes to `package.json`, so the entry-point restriction is left for a release that may touch it.
11. **Low — out-of-range scalars exposed an address they could not sign for.** `LocalPrivateKeySigner` rejects `d <= 0` and `d >= N` at construction, before deriving an address.

### Review of these fixes (d4ce9ed)

An independent review of the fixes above reported five findings. Regression tests are in `test/review-findings.test.mjs`; each fails on d4ce9ed and passes now.

- **High — a per-order lock was broken as stale after 60 s while its holder was still working, so a concurrent retry signed a second Permit2.** Both locks (`order-<hash>.json.lock` and `daily-spend.json.lock`) are now lease directories: a directory holding one `owner-<pid>-<random>` file, moved into place by a single atomic rename. The holder refreshes the owner file's mtime every 5 s while it works; a lock is stale only after 60 s without a refresh *and* when its owner pid is not alive on this host, so a slow status, capabilities or signer call never loses the lock. `execute()` re-checks the lock and re-reads the saved authorization immediately before reserving budget and signing, and `adjustSpend()` re-checks the lock before writing the ledger; a lost lock aborts with `lost <lock> to another imd process; refusing to continue`. Release unlinks only this process's own owner file and removes the directory only while it is empty. This supersedes the O_EXCL lock-file description under finding 1 and 2 above; a lock file left by the previous version is honoured and broken by mtime only.
- **Medium — several waiters could each delete the same stale ledger lock and each create their own, letting two processes exceed the daily cap.** With the lease directories, breaking a stale lock removes the owner file by its exact name and the directory only while empty, both of which fail for anyone but the first breaker, and acquisition is one rename; no waiter can remove a lock another process holds.
- **Low — a parseable but incomplete or garbled saved authorization was treated as absent or expired.** `readAuthorization()` now requires `order`, a `YYYY-MM-DD` `day`, integer `amount` and `deadline`, and non-empty `header` and `quoteSignature`, and throws the static `saved payment authorization corrupt; refusing to sign` on anything else, without releasing the reservation or touching the file.
- **Info — a replacement was signed the instant the local clock passed the saved deadline.** A saved authorization is treated as live until 30 s past its Permit2 deadline, covering clock skew against `block.timestamp`; status is still read before either path.
- **Info — the `package.json` exports map of finding 10 is still not included**, for the reason given under finding 10: this revision's rules forbid changes to `package.json`. The key-validation half of the finding is in place.

Also: `test/paid-flow.test.mjs` now returns the real `{ created, order: { quote } }` shape from the mock quote endpoint, keeps the order `quoted` until it is paid, and isolates the ledger under a temporary `XDG_STATE_HOME`. `test/ImdSdkVectors.t.sol` recovers the fixed Permit2 and QuoteApproval vectors with `ecrecover` so `forge test` cross-checks the SDK's EIP-712 hashing and signing.
