// ER1 — standalone offline verifier, BROWSER (WebCrypto) implementation.
//
// A third re-implementation of the ER1 verifier that runs anywhere WebCrypto does: a browser page,
// a worker, or any modern JS runtime that exposes `globalThis.crypto.subtle`. It uses ONLY
// subtle.digest("SHA-256") + subtle.verify("Ed25519"), TextEncoder, and atob — no runtime-specific
// modules, no file access, no networking primitives, no third-party crypto. It reproduces
// `er1_verify.mjs` byte-for-byte: the same RFC 8785–compatible canonical JSON, the same Ed25519
// check over the SHA-256 digest of the canonical body, the same constraint predicate and verdict
// recomputation. Any receipt (or tamper) that VERIFIES/FAILS under the two reference verifiers
// must do the same here — golden_vectors.json is the contract (see CONFORMANCE.md).
//
// Because WebCrypto is asynchronous, `verify` / `verifyJson` / `receiptHash` return Promises; the
// RESULT SHAPE and every error string are identical to er1_verify.mjs.
//
// Key handling: a receipt's `signature.public_key` is the base64url of the raw 32-byte Ed25519
// public key. The reference .mjs imports it as a JWK (kty OKP, crv Ed25519, x = that base64url);
// here the same 32 bytes are imported with subtle.importKey("raw", ...) — identical key material,
// no SPKI/DER wrapping involved. Runtimes that lack WebCrypto Ed25519 (feature-detected with a
// known-valid RFC 8032 test key) throw Er1UnsupportedCryptoError("browser lacks WebCrypto
// Ed25519") instead of reporting a misleading FAILED.
//
// What it certifies: the verdict correctly follows from the recorded, signed pre-state — NOT the
// empirical truth of the constraints ("garbage in, certified garbage out").

// ── typed capability error ──
export class Er1UnsupportedCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = "Er1UnsupportedCryptoError";
    this.code = "ER1_WEBCRYPTO_ED25519_UNSUPPORTED";
  }
}

// RFC 8032 §7.1 TEST 1 public key — a known-valid Ed25519 point, used only to probe support.
const PROBE_KEY = Uint8Array.from([
  0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
  0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
]);

let ed25519Confirmed = false; // cache positive detection only; failures re-probe (and re-throw)

async function ensureEd25519() {
  if (ed25519Confirmed) return;
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    throw new Er1UnsupportedCryptoError(
      "browser lacks WebCrypto Ed25519 (crypto.subtle unavailable — a secure context is required)");
  }
  try {
    await subtle.importKey("raw", PROBE_KEY, { name: "Ed25519" }, false, ["verify"]);
  } catch (e) {
    throw new Er1UnsupportedCryptoError(
      `browser lacks WebCrypto Ed25519 (importKey probe failed: ${e && e.name ? e.name : e})`);
  }
  ed25519Confirmed = true;
}

// ── canonical JSON (RFC 8785–compatible) — vendored verbatim from the spec ──
function escapeString(s) {
  s = s.normalize("NFC");
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
    else if (cp < 0x7f) out += ch;
    else if (cp <= 0xffff) out += "\\u" + cp.toString(16).padStart(4, "0");
    else {
      const v = cp - 0x10000;
      const hi = 0xd800 + (v >> 10), lo = 0xdc00 + (v & 0x3ff);
      out += "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0");
    }
  }
  return out + '"';
}

function fmtNumber(n) {
  if (!Number.isFinite(n)) throw new Error("non-finite number");
  if (Object.is(n, -0)) return "0";
  return String(n); // ECMA ToString — the reference er1_verify.py's float path mirrors
}

function canon(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return fmtNumber(v);
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") {
    // NFC BEFORE ordering — see the note in er1_verify.py::_canon. Sorting raw
    // keys and normalizing at emit time can mis-order and can emit duplicates.
    const norm = new Map();
    for (const k of Object.keys(v)) {
      const nk = k.normalize("NFC");
      if (norm.has(nk)) throw new Error("duplicate object key after NFC normalization: " + nk);
      norm.set(nk, v[k]);
    }
    const keys = [...norm.keys()].sort(); // default UTF-16 code-unit order == python _utf16_key
    return "{" + keys.map((k) => escapeString(k) + ":" + canon(norm.get(k))).join(",") + "}";
  }
  throw new TypeError("cannot canonicalize " + typeof v);
}

const canonicalBytes = (v) => new TextEncoder().encode(canon(v));

const toHex = (buf) =>
  Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(bytes) {
  return "sha256:" + toHex(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

// base64url → bytes without runtime-specific helpers. atob is strict: malformed input throws,
// which the signature check treats as an invalid signature — same verdict as the references.
function b64urlToBytes(s) {
  let b64 = String(s).replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── the conflict predicate — vendored verbatim from the spec ──
function parseVer(s) {
  return String(s).trim().split(".").map((part) => {
    let num = "";
    for (const ch of part) { if (ch >= "0" && ch <= "9") num += ch; else break; }
    return num ? parseInt(num, 10) : 0;
  });
}
function verCmp(a, b) {
  const pa = parseVer(a), pb = parseVer(b), n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}
function compatible(proposed, constraint) {
  // PEP 440 compatible-release (~=): proposed >= constraint AND shares its prefix (all but the
  // constraint's last component must match). ~=2.0 allows 2.5 not 3.0; ~=2.0.1 allows 2.0.5 not 2.1.0.
  if (verCmp(proposed, constraint) < 0) return false;
  const cv = parseVer(constraint);
  if (cv.length < 2) return true;
  const prefix = cv.slice(0, -1);
  const pv = parseVer(proposed);
  for (let i = 0; i < prefix.length; i++) if ((pv[i] ?? 0) !== prefix[i]) return false;
  return true;
}
function satisfies(proposed, constraint) {
  const c = constraint.trim();
  for (const op of [">=", "<=", "==", "~=", ">", "<", "="]) {
    if (c.startsWith(op)) {
      const target = c.slice(op.length).trim();
      if (op === "~=") return compatible(proposed, target);
      const cmp = verCmp(proposed, target);
      return { ">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0,
               "==": cmp === 0, "=": cmp === 0 }[op];
    }
  }
  return verCmp(proposed, c) === 0;
}
function conflict(beliefs, asserts) {
  for (const b of beliefs) {
    if ((b.status ?? "active") !== "active" || b.source_kind !== "deterministic") continue;
    const { entity: ent, rule, value: val } = b;
    if (rule === "excludes") {
      if (Object.hasOwn(asserts, ent)) return [b.belief_id, "BANNED_ENTITY"];
    } else if (Object.hasOwn(asserts, ent)) {
      const proposed = String(asserts[ent]);
      if (rule === "equals" && proposed !== val) return [b.belief_id, "SUPERSEDED_VALUE"];
      if (rule === "satisfies" && !satisfies(proposed, val)) return [b.belief_id, "CONSTRAINT_VIOLATION"];
    }
  }
  return null;
}

// ── verification ──
const body = (r) => ({ ...r, signature: null });

export async function receiptHash(r) {
  return sha256Hex(canonicalBytes(body(r)));
}

async function verifySignature(r) {
  const sb = r.signature;
  if (!sb || sb.algorithm !== "ed25519") return false;
  try {
    // The signed message is the SHA-256 digest of the canonical body (matches er1_verify.py and
    // er1_verify.mjs; pinned by golden_vectors.json). subtle.verify with { name: "Ed25519" } over
    // that 32-byte message is plain Ed25519 — identical to both references, as the vectors prove.
    const subtle = globalThis.crypto.subtle;
    const digest = await subtle.digest("SHA-256", canonicalBytes(body(r)));
    const pub = await subtle.importKey(
      "raw", b64urlToBytes(sb.public_key), { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, pub, b64urlToBytes(sb.signature),
                               new Uint8Array(digest));
  } catch {
    return false;
  }
}

export async function verify(r) {
  await ensureEd25519(); // throws Er1UnsupportedCryptoError where Ed25519 WebCrypto is missing
  const errors = [], checks = {};

  checks.signature = await verifySignature(r);
  if (!checks.signature) errors.push("signature: invalid or missing");

  const a = r.action ?? {};
  const expect = await sha256Hex(canonicalBytes(
    { tool: a.tool ?? "", asserts: a.asserts ?? {}, resource: a.resource ?? "" }));
  checks.binding = (r.action_binding ?? {}).args_hash === expect;
  if (!checks.binding) errors.push("action_binding: args_hash mismatch");

  const beliefs = r.beliefs ?? [];
  checks.state_root = r.pre_state_root === await sha256Hex(canonicalBytes(beliefs));
  if (!checks.state_root) errors.push("pre_state_root mismatch");

  const c = conflict(beliefs, a.asserts ?? {});
  const recomputed = c !== null ? "HALT" : "ALLOW";
  const recorded = r.decision ?? {};
  checks.verdict = recomputed === recorded.verdict;
  if (!checks.verdict) errors.push(`verdict: recomputed ${recomputed} vs recorded ${JSON.stringify(recorded.verdict)}`);
  if (c !== null) {
    if (recorded.conflicting_belief_id !== c[0]) errors.push("verdict: conflicting_belief_id mismatch");
    if (recorded.reason_code !== c[1]) errors.push("verdict: reason_code mismatch");
  }

  return { ok: errors.length === 0, recomputedVerdict: recomputed, checks, errors };
}

export async function verifyJson(text) {
  return verify(JSON.parse(text));
}
