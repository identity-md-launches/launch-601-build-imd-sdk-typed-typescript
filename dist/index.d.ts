export type Address = `0x${string}`;
export type Decimal = string | bigint;
export type Action =
  | 'job.open'
  | 'job.continue'
  | 'launch.open'
  | 'workflow.open'
  | 'oracle.request'
  | 'schedule.create'
  | 'schedule.topup';

export interface JobFile {
  name: string;
  path: string;
  hash?: string;
  mediaType: string;
  bytes?: number;
  submissionHash?: string;
}

export interface JobStep {
  skill: string;
  key?: string;
  dependsOn?: string[];
  objective?: string;
  acceptanceCriteria?: string[];
  paths?: string[];
  references?: string[];
  inputs?: JobFile[];
  outputs?: JobFile[];
  variables?: Record<string, string>;
}

export interface Economics {
  poolBps?: number;
  initialMarketCapWei?: string;
  remainderTo?: Address;
}

export interface JobOpenInput {
  objective: string;
  skill?: string;
  template?: 'single' | 'impl_tests' | 'impl_tests_review' | 'multi_contract' | 'fuzz' | 'research' | 'audit';
  shape?: 'chain' | 'fan_out_join' | 'dag';
  steps?: JobStep[];
  references?: string[];
  repoUrl?: string;
  baseCommit?: string;
  contracts?: string[];
  paths?: string[];
  inputs?: JobFile[];
  outputs?: JobFile[];
  github?: boolean;
  ipfs?: boolean | string;
  onchain?: true | 'univ4_hook' | 'evm_project' | 'custom_token';
  chainId?: number;
  pairWith?: 'eth' | 'imd';
  economics?: Economics;
  projectPath?: string | null;
  runs?: number;
  rubric?: { contains: string[]; mayNotRestOn?: string[] };
  panelSize?: number;
  panelQuorum?: number;
  minCitations?: number;
}

export interface JobContinueInput extends Omit<JobOpenInput, 'repoUrl' | 'baseCommit' | 'onchain'> {
  parentJobId: string;
}

export interface LaunchOpenInput extends JobOpenInput {
  onchain: true | 'univ4_hook' | 'evm_project' | 'custom_token';
}

export interface WorkflowOpenInput {
  request: string;
  context?: string;
  draft: JobOpenInput;
  permissions: {
    github?: boolean;
    ipfs?: boolean | string;
    onchain: { kind: 'univ4_hook' | 'evm_project' | 'custom_token'; chainId: number };
  };
}

export interface OracleRequestInput {
  v: 1;
  question: string;
  chainId: number;
  window: { hours: number } | { fromBlock: number; toBlock: number };
  answerType: 'bool' | 'address' | 'bytes32' | 'uint256' | 'address[]' | 'bytes32[]';
  evidence?: 'chain' | 'panel';
  head?: number;
  panelSize: number;
  quorum: number;
  validForSeconds: number;
  definitions?: Record<string, string>;
  guards?: {
    allow?: string[];
    deny?: string[];
    mustHaveCode?: boolean;
    min?: string;
    max?: string;
    sources?: string[];
    minSources?: number;
  };
  toleranceBps?: number;
  consumer?: { chainId: number; verifyingContract: Address };
  allowAmbiguous?: boolean;
}

export interface ScheduleCreateInput {
  label: string;
  action: 'oracle.request' | 'job.open';
  input: OracleRequestInput | JobOpenInput;
  cadence: { every: string } | { cron: string; tz?: string };
  runs: number;
  continue?: boolean;
  startAt?: string;
}

export interface ScheduleTopupInput {
  scheduleId: string;
  runs: number;
}

export interface Payment {
  network: string;
  asset: Address;
  amount: string;
  payTo: Address;
  decimals: number;
  scheme?: 'exact';
}

export interface Policy {
  action: string;
  version: string;
  payment: Payment;
  quoteTtlSeconds: number;
}

export interface LaunchPairing {
  pairWith: string;
  currency: Address;
  symbol: string;
  name: string;
  decimals: number;
  kinds: string[];
}

export interface LaunchChain {
  chainId: number;
  name: string;
  testnet: boolean;
  kinds: string[];
  pairings: LaunchPairing[];
}

export interface CapabilitiesAuthentication {
  scheme: string;
  tokenBytes: number;
  encoding: string;
}

export interface CapabilitiesPayment {
  x402Version: number;
  scheme: 'exact';
  assetTransferMethod: 'permit2';
  quoteApproval: string;
}

export interface Launches {
  defaultChainId: number;
  chains: LaunchChain[];
}

export interface Capabilities {
  actions: Policy[];
  limits: Record<string, Record<string, number>>;
  authentication: CapabilitiesAuthentication;
  payment: CapabilitiesPayment;
  launches?: Launches;
  pricedPer?: Record<string, string>;
}

export interface QuoteTerms {
  purchase: 'action-admission';
  resultGuaranteed: false;
}

export interface Quote {
  v: 1;
  id: string;
  action: string;
  policyVersion: string;
  inputHash: string;
  issuedAt: number;
  expiresAt: number;
  payment: Payment & { scheme: 'exact' };
  terms: QuoteTerms;
  quoteHash: string;
  unitAmount?: string;
  runs?: number;
  payer?: Address;
}

export interface Order {
  id: string;
  requestKey: string;
  status: 'quoted' | 'expired' | 'payment_pending' | 'payment_failed' | 'paid';
  quote: Quote;
  inputJson: string;
  createdAt: string;
  paidAt: string | null;
}

export interface OrderStatus {
  status: 'quoted' | 'expired' | 'payment_pending' | 'payment_failed' | 'admission_pending' | 'admitted';
  order: Order;
  payment: Record<string, unknown> | null;
  admission: Record<string, unknown> | null;
}

export interface Challenge {
  x402Version: 2;
  resource: Record<string, unknown>;
  accepts: Array<{
    scheme: 'exact';
    network: string;
    asset: Address;
    amount: string;
    payTo: Address;
    maxTimeoutSeconds: number;
    extra?: Record<string, unknown>;
  }>;
  quote: Quote;
  requesterScopeHash: string;
  resourceUrl: string;
  input: unknown;
}

export interface CheckFact {
  id: string;
  label: string;
  state: string;
  required: boolean;
}

export interface CheckMessage {
  code: string;
  detail: string;
  node?: string;
}

export interface CheckResult {
  action: string;
  kind: string;
  plan: unknown[];
  facts: CheckFact[];
  judged: boolean;
  blockers: CheckMessage[];
  suggestions: CheckMessage[];
}

export interface ImportSource {
  kind: 'code' | 'contracts' | 'site';
  repoUrl: string;
  baseCommit: string;
  owner: string;
  repo: string;
  ref: string;
  sizeKb: number;
}

export interface ImportResult {
  ok: boolean;
  source: ImportSource;
}

export interface Job {
  id: string;
  state: string;
  template: string;
  objective: string;
  blockedReason: string | null;
  createdAt: string;
  updatedAt: string;
  paidBy: Address | null;
  parentJobId: string | null;
  project: Record<string, unknown> | null;
  nodes: unknown[];
  reviews: unknown[];
  [field: string]: unknown;
}

export interface Schedule {
  id: string;
  label: string;
  action: string;
  status: string;
  cadence: Record<string, unknown>;
  runs: { total: number; remaining: number };
  owner: Address;
  paid: boolean;
  nextRunAt: string | null;
  [field: string]: unknown;
}

export interface SchedulesResult {
  count: number;
  schedules: Schedule[];
}

export interface DryRunResult {
  dryRun: true;
  order: Pick<Order, 'id'>;
  message: string;
}

export type PayResult = OrderStatus | DryRunResult;

export interface Signer {
  address: Address;
  signTypedData(typed: TypedData): Promise<`0x${string}`>;
}

export interface TypedData {
  domain: Record<string, unknown>;
  types: Record<string, { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface ImdClientOptions {
  baseUrl?: string;
  token?: string;
  signer?: Signer;
  maxPerRequest?: Decimal;
  maxPerDay?: Decimal;
  fetch?: typeof fetch;
}

export interface PayOptions {
  execute?: boolean;
}

export class ImdError extends Error {
  status: number;
  body: unknown;
}

export class LocalPrivateKeySigner implements Signer {
  constructor(privateKey: string);
  address: Address;
  signTypedData(typed: TypedData): Promise<`0x${string}`>;
}

export class ImdClient {
  constructor(options?: ImdClientOptions);
  capabilities(): Promise<Capabilities>;
  check(action: Action | string, input: object): Promise<CheckResult>;
  importRepo(url: string, kind?: 'code' | 'contracts' | 'site'): Promise<ImportResult>;
  quote(
    action: Action | string,
    input:
      | JobOpenInput
      | JobContinueInput
      | LaunchOpenInput
      | WorkflowOpenInput
      | OracleRequestInput
      | ScheduleCreateInput
      | ScheduleTopupInput
      | object,
  ): Promise<{ created: boolean; order: Order }>;
  pay(order: string | Pick<Order, 'id'>, signer?: Signer, options?: PayOptions): Promise<PayResult>;
  status(order: string | Pick<Order, 'id'>): Promise<OrderStatus>;
  waitFor(
    order: string | Pick<Order, 'id'>,
    options?: { intervalMs?: number; timeoutMs?: number },
  ): Promise<OrderStatus>;
  job(id: string): Promise<Job>;
  jobReport(id: string): Promise<string>;
  schedules(owner: string): Promise<SchedulesResult>;
}

export const API_URL: string;
export const IMD_TOKEN: Address;
export const PERMIT2: Address;
export const X402_PERMIT2_PROXY: Address;
export function createClient(options?: ImdClientOptions): ImdClient;
