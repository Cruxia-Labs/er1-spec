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

// ── soundness limits + typed structural error (mirrors er1_verify.py) ──
const MAX_DEPTH = 100;

export class Er1MalformedReceipt extends Error {}

const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const nfc = (s) => s.normalize("NFC");

// ── canonical JSON — vendored verbatim from the spec ──
function escapeString(s) {
  s = nfc(s);
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

// Integers only, and only those both languages represent exactly — see er1_verify.py::_number.
// ECMAScript ToString and Python repr share no number grammar, so emitting a float means two
// conformant verifiers can disagree about the canonical bytes of the same document.
function fmtNumber(n) {
  if (!Number.isFinite(n)) throw new Er1MalformedReceipt("non-finite number");
  if (!Number.isInteger(n)) {
    throw new Er1MalformedReceipt(`non-integral number ${n} is not canonicalizable (integers only)`);
  }
  if (Math.abs(n) > Number.MAX_SAFE_INTEGER) {
    throw new Er1MalformedReceipt(
      `integer ${n} is outside the exactly-representable range (|n| <= 2**53-1)`);
  }
  if (Object.is(n, -0)) return "0";
  return String(n);
}

function canon(v, depth = 0) {
  if (depth > MAX_DEPTH) throw new Er1MalformedReceipt(`nesting deeper than ${MAX_DEPTH} levels`);
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return fmtNumber(v);
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) return "[" + v.map((x) => canon(x, depth + 1)).join(",") + "]";
  if (typeof v === "object") {
    // NFC BEFORE ordering — see the note in er1_verify.py::_canon. Sorting raw
    // keys and normalizing at emit time can mis-order and can emit duplicates.
    const norm = new Map();
    for (const k of Object.keys(v)) {
      const nk = k.normalize("NFC");
      if (norm.has(nk)) {
        throw new Er1MalformedReceipt("duplicate object key after NFC normalization: " + nk);
      }
      norm.set(nk, v[k]);
    }
    const keys = [...norm.keys()].sort(); // default UTF-16 code-unit order == python _utf16_key
    return "{" + keys.map((k) => escapeString(k) + ":" + canon(norm.get(k), depth + 1)).join(",") + "}";
  }
  throw new Er1MalformedReceipt("cannot canonicalize " + typeof v);
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

// ── structural validation — runs BEFORE the predicate, and fails closed ──
const VERDICTS = new Set(["ALLOW", "HALT"]);
const RULES = new Set(["equals", "excludes", "satisfies"]);
const STATUSES = new Set(["active", "superseded"]);
const SOURCE_KINDS = new Set(["deterministic", "nl_extracted"]);
const BELIEF_CLASSES = new Set(["CERTIFIED", "BEST_EFFORT"]);

function requireStr(obj, field, where) {
  const v = obj[field];
  if (typeof v !== "string") {
    throw new Er1MalformedReceipt(
      `${where}.${field} must be a string, got ${v === null ? "null" : typeof v}`);
  }
  return v;
}

export function validateReceipt(r) {
  if (!isPlainObject(r)) throw new Er1MalformedReceipt("receipt is not a JSON object");
  if ("receipts" in r) {
    throw new Er1MalformedReceipt(
      "document carries both receipt fields and a `receipts` array — ambiguous");
  }
  const a = r.action;
  if (!isPlainObject(a)) throw new Er1MalformedReceipt("action must be an object");
  requireStr(a, "tool", "action");
  requireStr(a, "resource", "action");
  if (!isPlainObject(a.asserts)) throw new Er1MalformedReceipt("action.asserts must be an object");
  for (const [k, val] of Object.entries(a.asserts)) {
    if (typeof val !== "string") {
      throw new Er1MalformedReceipt(
        `action.asserts[${JSON.stringify(k)}] must be a string, got ${val === null ? "null" : typeof val}`);
    }
  }
  if (!isPlainObject(r.action_binding)) {
    throw new Er1MalformedReceipt("action_binding must be an object");
  }
  if (!Array.isArray(r.beliefs)) throw new Er1MalformedReceipt("beliefs must be an array");
  r.beliefs.forEach((b, i) => {
    if (!isPlainObject(b)) throw new Er1MalformedReceipt(`beliefs[${i}] is not an object`);
    const status = b.status ?? "active";
    if (!STATUSES.has(status)) {
      throw new Er1MalformedReceipt(`beliefs[${i}].status ${JSON.stringify(status)} is not a known status`);
    }
    if (!SOURCE_KINDS.has(b.source_kind)) {
      throw new Er1MalformedReceipt(
        `beliefs[${i}].source_kind ${JSON.stringify(b.source_kind)} is not a known source_kind`);
    }
    if ("belief_class" in b && !BELIEF_CLASSES.has(b.belief_class)) {
      throw new Er1MalformedReceipt(
        `beliefs[${i}].belief_class ${JSON.stringify(b.belief_class)} is not a known belief_class`);
    }
    if (status === "active" && b.source_kind === "deterministic") {
      requireStr(b, "belief_id", `beliefs[${i}]`);
      requireStr(b, "entity", `beliefs[${i}]`);
      const rule = requireStr(b, "rule", `beliefs[${i}]`);
      if (!RULES.has(rule)) {
        throw new Er1MalformedReceipt(`beliefs[${i}].rule ${JSON.stringify(rule)} is not a known rule`);
      }
      if (rule !== "excludes") requireStr(b, "value", `beliefs[${i}]`);
    }
  });
  if (!isPlainObject(r.decision)) throw new Er1MalformedReceipt("decision must be an object");
  if (!VERDICTS.has(r.decision.verdict)) {
    throw new Er1MalformedReceipt(
      `decision.verdict ${JSON.stringify(r.decision.verdict)} is not one of ALLOW, HALT`);
  }
  // The whole body must be canonicalizable, anywhere in the document — a receipt carrying a
  // number or nesting depth we cannot serialize exactly has no well-defined signed form.
  canonicalBytes(body(r));
}

// ── the conflict predicate — vendored verbatim from the spec ──
// Strict dotted-numeric parse; null when the string is not a version.
function parseVer(s) {
  const text = String(s).trim();
  if (!text) return null;
  const out = [];
  for (const part of text.split(".")) {
    if (!part || ![...part].every((ch) => ch >= "0" && ch <= "9")) return null;
    out.push(Number(part));
    if (!Number.isSafeInteger(out[out.length - 1])) return null;
  }
  return out;
}
function verCmp(pa, pb) {
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}
function compatible(proposed, constraint) {
  if (verCmp(proposed, constraint) < 0) return false;
  if (constraint.length < 2) return true;
  const prefix = constraint.slice(0, -1);
  for (let i = 0; i < prefix.length; i++) if ((proposed[i] ?? 0) !== prefix[i]) return false;
  return true;
}
function satisfies(proposedRaw, constraintRaw) {
  const c = String(constraintRaw).trim();
  for (const op of [">=", "<=", "==", "~=", ">", "<", "="]) {
    if (c.startsWith(op)) {
      const target = parseVer(c.slice(op.length));
      const proposed = parseVer(proposedRaw);
      if (target === null || proposed === null) {
        throw new Er1MalformedReceipt(
          `cannot evaluate ${op} between ${JSON.stringify(String(proposedRaw))} and ${JSON.stringify(c)}: not versions`);
      }
      if (op === "~=") return compatible(proposed, target);
      const cmp = verCmp(proposed, target);
      return { ">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0,
               "==": cmp === 0, "=": cmp === 0 }[op];
    }
  }
  const target = parseVer(c), proposed = parseVer(proposedRaw);
  if (target === null || proposed === null) return String(proposedRaw) === c;
  return verCmp(proposed, target) === 0;
}
function conflict(beliefs, asserts) {
  // Identity is normalized on both sides — canonical JSON normalizes these strings before they
  // are signed, so comparing raw would let one signed byte-string carry two identities.
  const normAsserts = new Map();
  for (const [k, v] of Object.entries(asserts)) {
    const nk = nfc(k);
    if (normAsserts.has(nk)) {
      throw new Er1MalformedReceipt(`action.asserts has two keys that are the same after NFC: ${nk}`);
    }
    normAsserts.set(nk, v);
  }
  for (const b of beliefs) {
    if ((b.status ?? "active") !== "active" || b.source_kind !== "deterministic") continue;
    const ent = nfc(b.entity), rule = b.rule, val = b.value;
    if (rule === "excludes") {
      if (normAsserts.has(ent)) return [b.belief_id, "BANNED_ENTITY"];
    } else if (normAsserts.has(ent)) {
      const proposed = String(normAsserts.get(ent));
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

// Small-order Ed25519 point encodings (libsodium's has_small_order blacklist). A signature built
// from these verifies against ANY message, so one constant block would forge every receipt.
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

async function verifySignature(r) {
  const sb = r.signature;
  if (!isPlainObject(sb) || sb.algorithm !== "ed25519") return false;
  if (typeof sb.public_key !== "string" || typeof sb.signature !== "string") return false;
  try {
    const pubRaw = b64urlToBytes(sb.public_key);
    const sigRaw = b64urlToBytes(sb.signature);
    if (pubRaw.length !== 32 || sigRaw.length !== 64) return false;
    if (SMALL_ORDER.has(toHex(pubRaw)) || SMALL_ORDER.has(toHex(sigRaw.subarray(0, 32)))) {
      return false;                       // a signature nobody produced must not verify
    }
  } catch {
    return false;
  }
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

export async function verify(r, trustedKeys = null) {
  await ensureEd25519(); // throws Er1UnsupportedCryptoError where Ed25519 WebCrypto is missing
  const errors = [], checks = {};

  let signer = null;
  if (isPlainObject(r) && isPlainObject(r.signature) && typeof r.signature.public_key === "string") {
    signer = r.signature.public_key;
  }

  // The signature is checked FIRST and unconditionally — see er1_verify.py::verify.
  checks.signature = await verifySignature(r);
  if (!checks.signature) errors.push("signature: invalid or missing");

  try {
    validateReceipt(r);
  } catch (exc) {
    return { ok: false, recomputedVerdict: null, checks,
             errors: [...errors, `malformed receipt: ${exc.message}`], signer };
  }

  if (trustedKeys !== null) {
    checks.trusted_signer = trustedKeys.has(signer);
    if (!checks.trusted_signer) errors.push(`signer not in pinned key set: ${JSON.stringify(signer)}`);
  }

  try {
  const a = r.action;
  const expect = await sha256Hex(canonicalBytes(
    { tool: a.tool, asserts: a.asserts, resource: a.resource }));
  const binding = r.action_binding;
  checks.binding = binding.args_hash === expect;
  if (!checks.binding) errors.push("action_binding: args_hash mismatch");
  // The binding names the request it binds to; a mismatch is a self-contradicting
  // receipt (the signature covers both). Mirrors er1_verify.py.
  if (binding.tool !== a.tool) errors.push("action_binding: tool does not mirror action.tool");
  if (binding.resource !== a.resource) errors.push("action_binding: resource does not mirror action.resource");

  const beliefs = r.beliefs;
  checks.state_root = r.pre_state_root === await sha256Hex(canonicalBytes(beliefs));
  if (!checks.state_root) errors.push("pre_state_root mismatch");

  const c = conflict(beliefs, a.asserts);
  const recomputed = c !== null ? "HALT" : "ALLOW";
  const recorded = r.decision;
  checks.verdict = recomputed === recorded.verdict;
  if (!checks.verdict) errors.push(`verdict: recomputed ${recomputed} vs recorded ${JSON.stringify(recorded.verdict)}`);
  if (c !== null) {
    if (recorded.conflicting_belief_id !== c[0]) errors.push("verdict: conflicting_belief_id mismatch");
    if (recorded.reason_code !== c[1]) errors.push("verdict: reason_code mismatch");
  }

  // er1.schema.json: post_state_root equals pre_state_root on ALLOW, null on
  // HALT (the action did not take effect). Mirrors er1_verify.py.
  const post = r.post_state_root ?? null;
  if (recomputed === "HALT") {
    checks.post_state_root = post === null;
    if (!checks.post_state_root) errors.push("post_state_root: must be null on HALT");
  } else {
    checks.post_state_root = post === r.pre_state_root;
    if (!checks.post_state_root) errors.push("post_state_root: must equal pre_state_root on ALLOW");
  }

    return { ok: errors.length === 0, recomputedVerdict: recomputed, checks, errors, signer };
  } catch (exc) {
    return { ok: false, recomputedVerdict: null, checks,
             errors: [...errors, `malformed receipt: ${exc.message}`], signer };
  }
}

export async function verifyJson(text, trustedKeys = null) {
  return verify(JSON.parse(text), trustedKeys);
}
