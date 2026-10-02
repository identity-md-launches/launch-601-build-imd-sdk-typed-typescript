export type Address = `0x${string}`;
export type Decimal = string | bigint;
export type Action = 'job.open' | 'job.continue' | 'launch.open' | 'workflow.open' | 'oracle.request' | 'schedule.create' | 'schedule.topup';

export interface JobFile { name: string; path: string; hash?: string; mediaType: string; bytes?: number; submissionHash?: string }
export interface JobStep { skill: string; key?: string; dependsOn?: string[]; objective?: string; acceptanceCriteria?: string[]; paths?: string[]; references?: string[]; inputs?: JobFile[]; outputs?: JobFile[]; variables?: Record<string, string> }
export interface Economics { poolBps?: number; initialMarketCapWei?: string; remainderTo?: Address }
export interface JobOpenInput { objective: string; skill?: string; template?: 'single'|'impl_tests'|'impl_tests_review'|'multi_contract'|'fuzz'|'research'|'audit'; shape?: 'chain'|'fan_out_join'|'dag'; steps?: JobStep[]; references?: string[]; repoUrl?: string; baseCommit?: string; contracts?: string[]; paths?: string[]; inputs?: JobFile[]; outputs?: JobFile[]; github?: boolean; ipfs?: boolean|string; onchain?: true|'univ4_hook'|'evm_project'|'custom_token'; chainId?: number; pairWith?: 'eth'|'imd'; economics?: Economics; projectPath?: string|null; runs?: number; rubric?: {contains: string[]; mayNotRestOn?: string[]}; panelSize?: number; panelQuorum?: number; minCitations?: number }
export interface JobContinueInput extends Omit<JobOpenInput, 'repoUrl'|'baseCommit'|'onchain'> { parentJobId: string }
export interface LaunchOpenInput extends JobOpenInput { onchain: true|'univ4_hook'|'evm_project'|'custom_token' }
export interface WorkflowOpenInput { request: string; context?: string; draft: JobOpenInput; permissions: {github?: boolean; ipfs?: boolean|string; onchain: {kind: 'univ4_hook'|'evm_project'|'custom_token'; chainId: number}} }
export interface OracleRequestInput { v: 1; question: string; chainId: number; window: {hours: number}|{fromBlock: number; toBlock: number}; answerType: 'bool'|'address'|'bytes32'|'uint256'|'address[]'|'bytes32[]'; evidence?: 'chain'|'panel'; head?: number; panelSize: number; quorum: number; validForSeconds: number; definitions?: Record<string,string>; guards?: {allow?: string[]; deny?: string[]; mustHaveCode?: boolean; min?: string; max?: string; sources?: string[]; minSources?: number}; toleranceBps?: number; consumer?: {chainId:number; verifyingContract:Address}; allowAmbiguous?: boolean }
export interface ScheduleCreateInput { label: string; action: 'oracle.request'|'job.open'; input: OracleRequestInput|JobOpenInput; cadence: {every:string}|{cron:string; tz?:string}; runs: number; continue?: boolean; startAt?: string }
export interface ScheduleTopupInput { scheduleId: string; runs: number }
export interface Signer { address: Address; signTypedData(typed: TypedData): Promise<`0x${string}`> }
export interface TypedData { domain: Record<string, unknown>; types: Record<string, {name:string;type:string}[]>; primaryType: string; message: Record<string, unknown> }
export interface ImdClientOptions { baseUrl?: string; token?: string; signer?: Signer; maxPerRequest?: Decimal; maxPerDay?: Decimal; fetch?: typeof fetch }
export interface PayOptions { execute?: boolean }
export class ImdError extends Error { status: number; body: unknown }
export class LocalPrivateKeySigner implements Signer { constructor(privateKey: string); address: Address; signTypedData(typed: TypedData): Promise<`0x${string}`> }
export class ImdClient {
  constructor(options?: ImdClientOptions);
  capabilities(): Promise<any>;
  check(action: Action|string, input: object): Promise<any>;
  importRepo(url: string, kind?: 'code'|'contracts'|'site'): Promise<any>;
  quote(action: Action|string, input: JobOpenInput|JobContinueInput|LaunchOpenInput|WorkflowOpenInput|OracleRequestInput|ScheduleCreateInput|ScheduleTopupInput|object): Promise<any>;
  pay(order: string|{id:string}, signer?: Signer, options?: PayOptions): Promise<any>;
  status(order: string|{id:string}): Promise<any>;
  waitFor(order: string|{id:string}, options?: {intervalMs?:number;timeoutMs?:number}): Promise<any>;
  job(id: string): Promise<any>;
  jobReport(id: string): Promise<any>;
  schedules(owner: string): Promise<any>;
}
export const API_URL: string; export const IMD_TOKEN: Address; export const PERMIT2: Address; export const X402_PERMIT2_PROXY: Address;
export function createClient(options?: ImdClientOptions): ImdClient;
