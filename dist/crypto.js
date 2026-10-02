// @ts-check
/** Minimal audited-surface primitives needed for EIP-712; no network or key storage. */
import { createHash, createHmac } from "node:crypto";

const MASK64 = (1n << 64n) - 1n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const G = [
  55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  32670510020758816978083085130507043184471273380659243275938904335757337482424n,
];
const RC = [
  1n,
  0x8082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x808bn,
  0x80000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x8an,
  0x88n,
  0x80008009n,
  0x8000000an,
  0x8000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x80000001n,
  0x8000000080008008n,
];
const ROT = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18,
  2, 61, 56, 14,
];
const te = new TextEncoder();
const bytes = (v) => (typeof v === "string" ? te.encode(v) : v);
const hex = (b) => `0x${Buffer.from(b).toString("hex")}`;
const unhex = (v) => new Uint8Array(Buffer.from(v.replace(/^0x/, ""), "hex"));
const concat = (...xs) => {
  const n = xs.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(n);
  let i = 0;
  for (const x of xs) {
    out.set(x, i);
    i += x.length;
  }
  return out;
};
const rotl = (x, n) =>
  n ? ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64 : x;

function keccakF(a) {
  for (let r = 0; r < 24; r++) {
    const c = Array.from(
      { length: 5 },
      (_, x) => a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20],
    );
    const d = Array.from(
      { length: 5 },
      (_, x) => c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1),
    );
    for (let i = 0; i < 25; i++) a[i] = (a[i] ^ d[i % 5]) & MASK64;
    const b = Array(25).fill(0n);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        a[x + 5 * y] =
          (b[x + 5 * y] ^
            (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y])) &
          MASK64;
    a[0] = (a[0] ^ RC[r]) & MASK64;
  }
}
function rotH(h, l, s) {
  if (s === 0) return h;
  if (s < 32) return (h << s) | (l >>> (32 - s));
  if (s === 32) return l;
  return (l << (s - 32)) | (h >>> (64 - s));
}
function rotL(h, l, s) {
  if (s === 0) return l;
  if (s < 32) return (l << s) | (h >>> (32 - s));
  if (s === 32) return h;
  return (h << (s - 32)) | (l >>> (64 - s));
}
/** The 32-bit implementation mirrors the Keccak reference permutation and avoids SHA3/Keccak confusion. */
function keccak32(s) {
  const b = new Uint32Array(10);
  let x = 1,
    y = 0;
  const pi = [],
    shifts = [];
  for (let round = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    pi.push(2 * (5 * y + x));
    shifts.push((((round + 1) * (round + 2)) / 2) % 64);
  }
  for (let round = 0; round < 24; round++) {
    for (let i = 0; i < 10; i++)
      b[i] = s[i] ^ s[i + 10] ^ s[i + 20] ^ s[i + 30] ^ s[i + 40];
    for (let i = 0; i < 10; i += 2) {
      const prev = (i + 8) % 10,
        next = (i + 2) % 10;
      const h = rotH(b[next], b[next + 1], 1) ^ b[prev],
        l = rotL(b[next], b[next + 1], 1) ^ b[prev + 1];
      for (let j = 0; j < 50; j += 10) {
        s[i + j] ^= h;
        s[i + j + 1] ^= l;
      }
    }
    let h = s[2],
      l = s[3];
    for (let t = 0; t < 24; t++) {
      const nh = rotH(h, l, shifts[t]),
        nl = rotL(h, l, shifts[t]),
        p = pi[t];
      h = s[p];
      l = s[p + 1];
      s[p] = nh;
      s[p + 1] = nl;
    }
    for (let j = 0; j < 50; j += 10) {
      for (let i = 0; i < 10; i++) b[i] = s[j + i];
      for (let i = 0; i < 10; i++)
        s[j + i] ^= ~b[(i + 2) % 10] & b[(i + 4) % 10];
    }
    s[0] ^= Number(RC[round] & 0xffffffffn);
    s[1] ^= Number(RC[round] >> 32n);
  }
}
/** @param {Uint8Array|string} value */
export function keccak256(value) {
  const input = bytes(value),
    rate = 136,
    state = new Uint8Array(200),
    words = new Uint32Array(state.buffer);
  let pos = 0;
  for (const byte of input) {
    state[pos++] ^= byte;
    if (pos === rate) {
      keccak32(words);
      pos = 0;
    }
  }
  state[pos] ^= 1;
  state[rate - 1] ^= 0x80;
  keccak32(words);
  return state.slice(0, 32);
}
export const sha256 = (v) =>
  new Uint8Array(createHash("sha256").update(bytes(v)).digest());
const mod = (a, m) => ((a % m) + m) % m;
function inv(a, m) {
  let [x, last, r, oldr] = [0n, 1n, m, mod(a, m)];
  while (r) {
    const q = oldr / r;
    [x, last] = [last - q * x, x];
    [oldr, r] = [r, oldr - q * r];
  }
  if (oldr !== 1n) throw new Error("non-invertible");
  return mod(last, m);
}
function add(A, B) {
  if (!A) return B;
  if (!B) return A;
  const [x, y] = A,
    [u, v] = B;
  if (x === u) {
    if (mod(y + v, P) === 0n) return null;
    return dbl(A);
  }
  const m = mod((v - y) * inv(u - x, P), P);
  return [mod(m * m - x - u, P), mod(m * (x - mod(m * m - x - u, P)) - y, P)];
}
function dbl(A) {
  if (!A || A[1] === 0n) return null;
  const m = mod(3n * A[0] * A[0] * inv(2n * A[1], P), P);
  const x = mod(m * m - 2n * A[0], P);
  return [x, mod(m * (A[0] - x) - A[1], P)];
}
function mul(k, A = G) {
  let out = null,
    p = A;
  while (k) {
    if (k & 1n) out = add(out, p);
    p = dbl(p);
    k >>= 1n;
  }
  return out;
}
const b32 = (n) => {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 255n);
    n >>= 8n;
  }
  return out;
};
const num = (x) => (typeof x === "bigint" ? x : BigInt(x));
const hmac = (key, data) =>
  new Uint8Array(createHmac("sha256", key).update(data).digest());

/**
 * Validate and normalize a private key at every public boundary; the static error never contains key material.
 * @param {unknown} privateKey
 */
function normalizeKey(privateKey) {
  if (
    typeof privateKey !== "string" ||
    !/^(0x)?[0-9a-fA-F]{64}$/.test(privateKey)
  )
    throw new Error("invalid private key");
  const d = BigInt(
    privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`,
  );
  if (d <= 0n || d >= N) throw new Error("invalid private key");
  return d;
}
/**
 * Deterministic RFC6979 secp256k1 signature with Ethereum recovery byte.
 * @param {string} privateKey
 * @param {Uint8Array} digest
 */
export function signDigest(privateKey, digest) {
  const d = normalizeKey(privateKey);
  const z = BigInt(hex(digest));
  let k = new Uint8Array(32),
    v = new Uint8Array(32).fill(1);
  const x = b32(d),
    h = b32(z);
  k = hmac(k, concat(v, new Uint8Array([0]), x, h));
  v = hmac(k, v);
  k = hmac(k, concat(v, new Uint8Array([1]), x, h));
  v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const nonce = BigInt(hex(v));
    if (nonce > 0n && nonce < N) {
      const R = mul(nonce);
      const r = R[0] % N;
      if (r) {
        let s = mod(inv(nonce, N) * (z + r * d), N);
        if (s) {
          let rec = Number(R[1] & 1n);
          if (s > N / 2n) {
            s = N - s;
            rec ^= 1;
          }
          return hex(concat(b32(r), b32(s), new Uint8Array([27 + rec])));
        }
      }
    }
    k = hmac(k, concat(v, new Uint8Array([0])));
    v = hmac(k, v);
  }
}
/** @param {string} privateKey */
export function addressFromPrivateKey(privateKey) {
  const Q = mul(normalizeKey(privateKey));
  return hex(keccak256(concat(b32(Q[0]), b32(Q[1]))).slice(12)).toLowerCase();
}
function deps(primary, types, seen = new Set()) {
  if (seen.has(primary)) return [];
  seen.add(primary);
  return [
    primary,
    ...Object.values(types[primary] || []).flatMap((f) =>
      types[f.type] ? deps(f.type, types, seen) : [],
    ),
  ];
}
function typeText(primary, types) {
  const d = deps(primary, types);
  return [primary, ...d.filter((x) => x !== primary).sort()]
    .map((n) => `${n}(${types[n].map((f) => `${f.type} ${f.name}`).join(",")})`)
    .join("");
}
function field(type, value, types) {
  if (types[type]) return keccak256(encodeStruct(type, value, types));
  if (type === "string") return keccak256(String(value));
  if (type === "bytes") return keccak256(unhex(value));
  if (type === "address") {
    const h = unhex(value);
    return concat(new Uint8Array(12), h);
  }
  if (/^bytes\d+$/.test(type)) {
    const h = unhex(value);
    return concat(h, new Uint8Array(32 - h.length));
  }
  if (/^u?int/.test(type)) return b32(num(value));
  throw new Error(`unsupported EIP-712 type ${type}`);
}
function encodeStruct(primary, value, types) {
  return concat(
    keccak256(typeText(primary, types)),
    ...types[primary].map((f) => field(f.type, value[f.name], types)),
  );
}
/**
 * @param {{domain: object, types: Record<string, {name: string, type: string}[]>, primaryType: string,
 * message: object}} typed
 */
export function typedDataDigest(typed) {
  const fields = [];
  if (typed.domain.name !== undefined)
    fields.push({ name: "name", type: "string" });
  if (typed.domain.version !== undefined)
    fields.push({ name: "version", type: "string" });
  if (typed.domain.chainId !== undefined)
    fields.push({ name: "chainId", type: "uint256" });
  if (typed.domain.verifyingContract !== undefined)
    fields.push({ name: "verifyingContract", type: "address" });
  const types = { ...typed.types, EIP712Domain: fields };
  return keccak256(
    concat(
      new Uint8Array([0x19, 1]),
      keccak256(encodeStruct("EIP712Domain", typed.domain, types)),
      keccak256(encodeStruct(typed.primaryType, typed.message, types)),
    ),
  );
}
/** A local key is intentionally opt-in; CLI reads it only from IMD_PRIVATE_KEY when executing. */
export class LocalPrivateKeySigner {
  #privateKey;
  /** @param {string} privateKey */ constructor(privateKey) {
    const d = normalizeKey(privateKey);
    this.#privateKey = `0x${d.toString(16).padStart(64, "0")}`;
    this.address = addressFromPrivateKey(this.#privateKey);
  }
  /**
   * @param {{domain: object, types: Record<string, {name: string, type: string}[]>, primaryType: string,
   * message: object}} typed
   */
  async signTypedData(
    typed,
  ) {
    return signDigest(this.#privateKey, typedDataDigest(typed));
  }
}
export const toHex = hex;
