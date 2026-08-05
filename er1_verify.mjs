#!/usr/bin/env node
// ER1 — standalone offline verifier, JavaScript reference implementation.
//
// A SECOND-LANGUAGE verifier for the Epistemic Receipt (ER1) format. It depends on nothing but
// Node's built-in `node:crypto` — no npm install, no network, no engine code. It reproduces
// `er1_verify.py` byte-for-byte: the same canonical JSON, the same Ed25519 check over the
// SHA-256 digest, the same constraint predicate and verdict recomputation. Two independent
// implementations agreeing on the same signed bytes is what makes ER1 a format anyone can
// check, not a log you have to trust.
//
//     node er1_verify.mjs receipt.json [...]              # verify receipt file(s)
//     node er1_verify.mjs --pubkey <key> receipt.json     # pin the signer you actually trust
//     node er1_verify.mjs golden_vectors.json             # self-test the published vectors
//
// What it certifies: the verdict correctly follows from the recorded, signed pre-state — NOT the
// empirical truth of the constraints ("garbage in, certified garbage out").
//
// SOUNDNESS RULES (v1.1, after the 2026-08-04 adversarial review) — every rule below exists
// because a receipt that should not have been trusted printed VERIFIED. The prose lives in
// er1_verify.py; this file must match it behaviour-for-behaviour, and tests/conformance_cases
// is run against both to prove it.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MAX_DEPTH = 100;
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2**53 - 1
const MAX_BYTES = 8 * 1024 * 1024;            // a receipt is a constraint snapshot, not a payload

export class Er1MalformedReceipt extends Error {}

// ── canonical JSON — vendored verbatim from the spec ──

// Deliberately NOT normalized — NFC is bound to the runtime's Unicode version (CPython 3.12
// ships 15.0, Node 24 ships 16.0; 20 code points compose in one and not the other), so
// normalizing made the signed bytes depend on the interpreter. RFC 8785 does not normalize.
function escapeString(s) {
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

// Integers only, and only those both languages represent exactly. Anything else is refused
// rather than guessed at: ECMAScript ToString and Python repr share no number grammar, so
// emitting a float means two conformant verifiers can disagree about the canonical bytes —
// which is a disagreement about whether a receipt was tampered with.
function fmtNumber(n) {
  if (!Number.isFinite(n)) throw new Er1MalformedReceipt("non-finite number");
  if (!Number.isInteger(n)) {
    throw new Er1MalformedReceipt(`non-integral number ${n} is not canonicalizable (integers only)`);
  }
  if (Math.abs(n) > MAX_SAFE_INT) {
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
    const keys = Object.keys(v).sort(); // default UTF-16 code-unit order == python _utf16_key
    return "{" + keys.map((k) => escapeString(k) + ":" + canon(v[k], depth + 1)).join(",") + "}";
  }
  throw new Er1MalformedReceipt("cannot canonicalize " + typeof v);
}

const canonicalBytes = (v) => Buffer.from(canon(v), "utf8");
const sha256Hex = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");

// Exposed for tests/differential_fuzz.py, which proves this file and er1_verify.py produce
// identical canonical bytes (or both refuse) across random documents.
export const canonicalJsonForFuzz = (v) => canon(v);

// ── structural validation — runs BEFORE the predicate, and fails closed ──
const VERDICTS = new Set(["ALLOW", "HALT"]);
const RULES = new Set(["equals", "excludes", "satisfies"]);
const STATUSES = new Set(["active", "superseded"]);
const SOURCE_KINDS = new Set(["deterministic", "nl_extracted"]);
const BELIEF_CLASSES = new Set(["CERTIFIED", "BEST_EFFORT"]);

const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

// Printable ASCII, the character set the IDENTITY fields are restricted to — the names used to
// look a constraint up. Within it, normalization is the identity function in every Unicode
// version, so two implementations cannot disagree about which constraint an action touches.
const isIdSafe = (s) => { for (const ch of s) { const c = ch.codePointAt(0); if (c < 0x20 || c > 0x7e) return false; } return true; };

function requireStr(obj, field, where, idSafe = false) {
  const v = obj[field];
  if (typeof v !== "string") {
    throw new Er1MalformedReceipt(`${where}.${field} must be a string, got ${v === null ? "null" : typeof v}`);
  }
  if (idSafe && !isIdSafe(v)) {
    throw new Er1MalformedReceipt(`${where}.${field} must be printable ASCII (it names a constraint)`);
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
    if (!isIdSafe(k)) {
      throw new Er1MalformedReceipt(
        `action.asserts key ${JSON.stringify(k)} must be printable ASCII (it names a constraint)`);
    }
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
    // No implicit default: `?? "active"` and Python's dict.get disagree on an explicit null,
    // so one verifier read the constraint as active and the other rejected the receipt.
    const status = b.status;
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
      requireStr(b, "belief_id", `beliefs[${i}]`, true);
      requireStr(b, "entity", `beliefs[${i}]`, true);
      const rule = requireStr(b, "rule", `beliefs[${i}]`, true);
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
// Strict dotted-numeric parse; null when the string is not a version. The old parser mapped
// any non-numeric component to 0, so `<2.0` was satisfied by "latest", "main" and "".
function parseVer(s) {
  // No trim(): ECMAScript's String.trim and Python's str.strip remove different whitespace
  // sets, which flipped verdicts between the two reference verifiers on the same bytes.
  const text = typeof s === "string" ? s : String(s);
  if (!text) return null;
  const out = [];
  for (const part of text.split(".")) {
    if (!part || ![...part].every((ch) => ch >= "0" && ch <= "9")) return null;
    out.push(Number(part));
    if (!Number.isSafeInteger(out[out.length - 1])) return null;  // stay exact, like Python
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
  if (constraint.length < 2) {
    // PEP 440: ~=2 is not a valid compatible-release clause — it would degenerate into an
    // unbounded >=2 and the pin would never gate anything.
    throw new Er1MalformedReceipt("~= needs at least two version components");
  }
  const prefix = constraint.slice(0, -1);
  for (let i = 0; i < prefix.length; i++) if ((proposed[i] ?? 0) !== prefix[i]) return false;
  return true;
}

function satisfies(proposedRaw, constraintRaw) {
  const c = typeof constraintRaw === "string" ? constraintRaw : String(constraintRaw);
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
  const normAsserts = new Map(Object.entries(asserts));
  for (const b of beliefs) {
    if (b.status !== "active" || b.source_kind !== "deterministic") continue;
    const ent = b.entity, rule = b.rule;
    if (rule === "excludes") {
      if (normAsserts.has(ent)) return [b.belief_id, "BANNED_ENTITY"];
    } else if (normAsserts.has(ent)) {
      const proposed = String(normAsserts.get(ent));
      if (rule === "equals" && proposed !== b.value) return [b.belief_id, "SUPERSEDED_VALUE"];
      if (rule === "satisfies" && !satisfies(proposed, b.value)) {
        return [b.belief_id, "CONSTRAINT_VIOLATION"];
      }
    }
  }
  return null;
}

// ── verification ──
const body = (r) => ({ ...r, signature: null });
export const receiptHash = (r) => sha256Hex(canonicalBytes(body(r)));

// Small-order Ed25519 point encodings (libsodium's has_small_order blacklist). A signature
// built from these verifies against ANY message, so one constant block would forge every
// receipt. Rejected for both the public key and the signature's R component.
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

// Ed25519 encodes the x-coordinate's sign in the HIGH BIT of byte 31, so every point has two
// accepted spellings that decode to the same point. Comparing all 32 bytes missed the sign-bit
// spellings of the identity (0100..0080, eeff..ffff); with A = identity the verification equation
// collapses to S*B == R, which R = base point, S = 1 satisfies for EVERY message — one constant
// signature block verified every receipt. libsodium masks s[31] & 127 first; so do we.
function isSmallOrder(raw) {
  const masked = Uint8Array.from(raw);
  masked[31] &= 0x7f;
  return SMALL_ORDER.has(Array.from(masked, (b) => b.toString(16).padStart(2, "0")).join(""));
}

// Strict, hand-rolled base64url — every runtime's decoder has its own leniency, so the same
// file verified in one implementation and failed in another. Nothing here is delegated.
const B64_ALPHABET = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

function strictB64url(s, expectLen) {
  if (typeof s !== "string") throw new Er1MalformedReceipt("signature field is not a string");
  for (const ch of s) {
    if (!B64_ALPHABET.has(ch)) throw new Er1MalformedReceipt("signature field is not unpadded base64url");
  }
  const expectChars = Math.ceil((expectLen * 8) / 6);
  if (s.length !== expectChars) {
    throw new Er1MalformedReceipt(`signature field must be exactly ${expectChars} base64url characters`);
  }
  const raw = Buffer.from(s, "base64url");
  if (raw.length !== expectLen) {
    throw new Er1MalformedReceipt(`signature field must decode to ${expectLen} bytes`);
  }
  // The final character's unused trailing bits are discarded by every decoder, so many
  // spellings decode to the same bytes. Pin the one canonical spelling.
  if (raw.toString("base64url") !== s) {
    throw new Er1MalformedReceipt("signature field is not canonical base64url");
  }
  return raw;
}

const b64Key = (s) => strictB64url(s, 32);
const toHexKey = (buf) => Buffer.from(buf).toString("hex");

function verifySignature(r) {
  const sb = r.signature;
  if (!isPlainObject(sb) || sb.algorithm !== "ed25519") return false;
  if (typeof sb.public_key !== "string" || typeof sb.signature !== "string") return false;
  try {
    const pubRaw = strictB64url(sb.public_key, 32);
    const sigRaw = strictB64url(sb.signature, 64);
    if (isSmallOrder(pubRaw) || isSmallOrder(sigRaw.subarray(0, 32))) {
      return false;                       // a signature nobody produced must not verify
    }
    const digest = createHash("sha256").update(canonicalBytes(body(r))).digest();
    const pub = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: pubRaw.toString("base64url") },
      format: "jwk",
    });
    return edVerify(null, digest, pub, sigRaw);
  } catch {
    return false;
  }
}

export function verify(r, trustedKeys = null) {
  const errors = [], checks = {};

  let signer = null;
  if (isPlainObject(r) && isPlainObject(r.signature) && typeof r.signature.public_key === "string") {
    signer = r.signature.public_key;
  }

  // The signature is checked FIRST and unconditionally — see er1_verify.py::verify.
  checks.signature = isPlainObject(r) ? verifySignature(r) : false;
  if (!checks.signature) errors.push("signature: invalid or missing");

  try {
    validateReceipt(r);
  } catch (exc) {
    return { ok: false, recomputedVerdict: null, checks,
             errors: [...errors, `malformed receipt: ${exc.message}`], signer };
  }

  if (trustedKeys !== null) {
    // Compare the 32 key BYTES, not the base64 text: the same key has several valid
    // spellings, and pinning must not be defeated by re-spelling it.
    let signerHex = null;
    try { signerHex = toHexKey(b64Key(signer)); } catch { signerHex = null; }
    const pinnedHex = new Set();
    for (const k of trustedKeys) { try { pinnedHex.add(toHexKey(b64Key(k))); } catch { /* skip */ } }
    checks.trusted_signer = signerHex !== null && pinnedHex.has(signerHex);
    if (!checks.trusted_signer) errors.push(`signer not in pinned key set: ${JSON.stringify(signer)}`);
  }

  try {
    const a = r.action;
    const expect = sha256Hex(canonicalBytes({ tool: a.tool, asserts: a.asserts, resource: a.resource }));
    const binding = r.action_binding;
    checks.binding = binding.args_hash === expect;
    if (!checks.binding) errors.push("action_binding: args_hash mismatch");
    if (binding.tool !== a.tool) errors.push("action_binding: tool does not mirror action.tool");
    if (binding.resource !== a.resource) errors.push("action_binding: resource does not mirror action.resource");

    const beliefs = r.beliefs;
    checks.state_root = r.pre_state_root === sha256Hex(canonicalBytes(beliefs));
    if (!checks.state_root) errors.push("pre_state_root mismatch");

    const c = conflict(beliefs, a.asserts);
    const recomputed = c !== null ? "HALT" : "ALLOW";
    const recorded = r.decision;
    checks.verdict = recomputed === recorded.verdict;
    if (!checks.verdict) {
      errors.push(`verdict: recomputed ${recomputed} vs recorded ${JSON.stringify(recorded.verdict)}`);
    }
    if (c !== null) {
      if (recorded.conflicting_belief_id !== c[0]) errors.push("verdict: conflicting_belief_id mismatch");
      if (recorded.reason_code !== c[1]) errors.push("verdict: reason_code mismatch");
    }

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

// ── CLI ──
// Discriminate a bundle from a bare receipt UNAMBIGUOUSLY: a document that presents as both is
// rejected, because an unsigned top-level `receipts` array used to decide what got verified.
// ── the one parse path ──
//
// Every rule that makes a document's reading unambiguous lives here, and it is shared with the
// browser build. JSON.parse cannot help with duplicate keys — by the time a reviver runs, the
// parser has already kept the last one — so the text is scanned directly. The previous
// implementation tried to do this with a reviver and was dead code: it tested a Set that was
// never written to, so Node verified documents Python refused.

function scanJsonForDuplicateKeys(text, collect = false) {
  const allKeys = [];
  let i = 0;
  const n = text.length;

  const readString = () => {                       // assumes text[i] === '"'
    let out = "";
    i++;
    while (i < n) {
      const c = text[i];
      if (c === "\\") {
        const e = text[i + 1];
        if (e === "u") {
          out += String.fromCharCode(parseInt(text.substr(i + 2, 4), 16));
          i += 6;
        } else {
          out += { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e] ?? e;
          i += 2;
        }
      } else if (c === '"') {
        i++;
        return out;
      } else {
        out += c;
        i++;
      }
    }
    throw new Er1MalformedReceipt("unterminated string in document");
  };

  // A real container stack — an earlier version guessed with lastIndexOf and never fired.
  const stack = [];                                 // {isObject, seen} per open container
  let expectKey = false;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      const str = readString();
      if (expectKey) {
        const top = stack[stack.length - 1];
        if (top && top.seen.has(str)) {
          throw new Er1MalformedReceipt(`duplicate object key in the document text: '${str}'`);
        }
        if (top) top.seen.add(str);
        if (collect) allKeys.push(str);
        expectKey = false;
      }
      continue;
    }
    if (c === "{") { stack.push({ isObject: true, seen: new Set() }); expectKey = true; }
    else if (c === "[") { stack.push({ isObject: false, seen: new Set() }); expectKey = false; }
    else if (c === "}" || c === "]") { stack.pop(); expectKey = false; }
    else if (c === ",") {
      const top = stack[stack.length - 1];
      expectKey = Boolean(top && top.isObject);
    }
    i++;
  }
  return allKeys;
}

// Every key the TEXT contains, in document order. Used to cross-check the parser: see
// loadDocument. Collected by the same scan that finds duplicates, so it costs nothing extra.
function scanJsonKeys(text) {
  return scanJsonForDuplicateKeys(text, true);
}

// Every key the PARSED object contains. Compared against the text reading — if a parser
// disagrees with the document about what its own keys are, the document has no single reading.
function parsedKeys(v, out = []) {
  if (Array.isArray(v)) { for (const x of v) parsedKeys(x, out); return out; }
  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) { out.push(k); parsedKeys(v[k], out); }
  }
  return out;
}

// Unpaired surrogates have no UTF-8 form, so they have no canonical byte form either. Checked in
// object KEYS as well as string values — the first version inspected only values, and a receipt
// with a surrogate in a key verified in Node while Python refused to load it.
function rejectLoneSurrogates(v) {
  if (typeof v === "string") {
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const next = v.charCodeAt(i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new Er1MalformedReceipt("string contains an unpaired surrogate");
        }
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        throw new Er1MalformedReceipt("string contains an unpaired surrogate");
      }
    }
  } else if (Array.isArray(v)) {
    for (const x of v) rejectLoneSurrogates(x);
  } else if (isPlainObject(v)) {
    for (const k of Object.keys(v)) {
      rejectLoneSurrogates(k);
      rejectLoneSurrogates(v[k]);
    }
  }
}

export function loadDocument(text) {
  const textKeys = scanJsonKeys(text);
  const doc = JSON.parse(text);
  // The parser is not trusted to read the document correctly. Node 24's JSON.parse can
  // misread an escaped object key ("\\u00e9" -> "\\") once the same process has parsed an
  // object containing a backslash-escaped key, so what a file MEANS depends on what was
  // parsed before it — and a signature computed over that misreading verified in Node while
  // Python refused the same bytes. Comparing the parser's keys against the ones the document
  // text actually contains closes the class without depending on any parser being correct.
  const seen = parsedKeys(doc).slice().sort();
  const want = textKeys.slice().sort();
  if (seen.length !== want.length || seen.some((k, idx) => k !== want[idx])) {
    throw new Er1MalformedReceipt(
      "document text and parsed reading disagree about object keys — no single reading");
  }
  rejectLoneSurrogates(doc);
  if (!isPlainObject(doc)) {
    throw new Er1MalformedReceipt("top-level JSON must be an object");
  }
  return doc;
}

function receiptsFrom(doc, label) {
  if (isPlainObject(doc) && Array.isArray(doc.receipts)) {
    if (["decision", "signature", "action", "beliefs"].some((k) => k in doc)) {
      return [[label, "AMBIGUOUS"]];
    }
    return doc.receipts.map((w, i) =>
      isPlainObject(w) && isPlainObject(w.receipt)
        ? [`${label}:${w.name}`, w.receipt]
        : [`${label}:entry[${i}]`, null]);
  }
  return [[label, doc]];
}

const USAGE =
  "usage: node er1_verify.mjs [--pubkey KEY]... <receipt.json | golden_vectors.json> [...]\n" +
  "  --pubkey KEY   pin a trusted signer (repeatable). Without it, a receipt is\n" +
  "                 verified against the key it carries — see SCOPE_OF_CERTIFICATION.md.\n";

function main(argv) {
  const pinned = new Set(), paths = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--pubkey") {
      if (i + 1 >= argv.length) {
        process.stderr.write("error: --pubkey needs a value\n" + USAGE);
        return 2;
      }
      pinned.add(argv[++i]);
      continue;
    }
    if ((argv[i] === "-h" || argv[i] === "--help") && i === 0) {
      process.stdout.write(USAGE);
      return 0;
    }
    paths.push(argv[i]);
  }
  if (paths.length === 0) {
    process.stderr.write(USAGE);
    return 2;
  }

  const trusted = pinned.size ? pinned : null;
  let allOk = true, checked = 0;
  for (const path of paths) {
    let doc;
    try {
      // Decode strictly: Node's "utf8" reader silently substitutes U+FFFD for malformed
      // bytes, so byte-tampered files verified here and were refused by Python — the file
      // to receipt mapping was many-to-one and byte-identity was gone.
      // A FIFO/device/directory blocks forever on read — a wedged CI gate with no verdict.
      // Refuse anything that is not a regular file before opening it.
      if (!statSync(path).isFile()) {
        throw new Er1MalformedReceipt("not a regular file");
      }
      const raw = readFileSync(path);
      if (raw.length > MAX_BYTES) {
        throw new Er1MalformedReceipt(
          `input exceeds ${MAX_BYTES} bytes — a receipt is a constraint snapshot, not a payload`);
      }
      doc = loadDocument(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    } catch (exc) {
      process.stdout.write(`FAILED ✗  ${path}  [could not load: ${exc.message}]\n`);
      allOk = false;
      continue;
    }
    for (const [label, r] of receiptsFrom(doc, path)) {
      checked++;
      if (r === null) {
        process.stdout.write(`FAILED ✗  ${label}  [malformed bundle entry: no receipt object]\n`);
        allOk = false;
        continue;
      }
      if (r === "AMBIGUOUS") {
        process.stdout.write(
          `FAILED ✗  ${label}  [ambiguous document: carries both receipt fields and a \`receipts\` array]\n`);
        allOk = false;
        continue;
      }
      const res = verify(r, trusted);
      const v = isPlainObject(r) && isPlainObject(r.decision) ? r.decision.verdict : undefined;
      const status = res.ok ? "VERIFIED ✓" : "FAILED ✗";
      let short;
      try {
        short = receiptHash(r).slice(0, 18) + "…";
      } catch {
        short = "<uncanonicalizable>";
      }
      let sigNote = typeof res.signer === "string" && res.signer.length > 12
        ? `signer=${res.signer.slice(0, 12)}…` : `signer=${res.signer}`;
      if (trusted === null && typeof res.signer === "string") sigNote += " (unpinned)";
      process.stdout.write(
        `${status}  ${label}  verdict=${v} (recomputed ${res.recomputedVerdict})  hash=${short}  ${sigNote}\n`);
      for (const e of res.errors) process.stdout.write(`    ! ${e}\n`);
      allOk = allOk && res.ok;
    }
  }
  if (checked === 0 && allOk) {
    // An empty bundle must never pass a CI gate by saying nothing.
    process.stderr.write("FAILED ✗  no receipts found in input\n");
    return 1;
  }
  return allOk ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.on("EPIPE", () => process.exit(0));
  process.exit(main(process.argv.slice(2)));
}
