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
// The binding, not two independent enums: a belief's class is a FUNCTION of where it came
// from. See er1_verify.py::BELIEF_CLASS_OF_SOURCE for why this exists.
const BELIEF_CLASS_OF_SOURCE = { deterministic: "CERTIFIED", nl_extracted: "BEST_EFFORT" };

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
    // Validated only WHEN PRESENT, and then never used — so er1.schema.json required it
    // while the verifier did not, and nothing tied the label to the thing it labels. A
    // producer could ship {source_kind: nl_extracted, belief_class: CERTIFIED}: an LLM's
    // guess wearing the word CERTIFIED. See er1_verify.py for the full note.
    // Absence must READ the same in every implementation, not merely be refused by all of them.
    // Python's dict.get returns None and renders "null"; JS gives undefined and rendered
    // "undefined" — so the three verifiers agreed on the verdict and disagreed on the message,
    // and the error strings are part of the spec. Normalised at the read, so the check and the
    // message cannot drift apart later either.
    const beliefClass = b.belief_class === undefined ? null : b.belief_class;
    if (!BELIEF_CLASSES.has(beliefClass)) {
      throw new Er1MalformedReceipt(
        `beliefs[${i}].belief_class ${JSON.stringify(beliefClass)} is not a known belief_class`);
    }
    if (BELIEF_CLASS_OF_SOURCE[b.source_kind] !== beliefClass) {
      throw new Er1MalformedReceipt(
        `beliefs[${i}].belief_class ${JSON.stringify(beliefClass)} contradicts source_kind ` +
        `${JSON.stringify(b.source_kind)} — ${JSON.stringify(b.source_kind)} beliefs are ` +
        `${BELIEF_CLASS_OF_SOURCE[b.source_kind]}`);
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

  // coverage.unevaluated_constraints carries semantics as of 1.0.1 (it is the declared set
  // checkUnevaluated recomputes), so when the name is present its shape must be exact.
  // Everything else under coverage stays unread, and an absent field is an empty declaration —
  // receipts that evaluated every constraint are untouched, byte for byte.
  // hasOwnProperty, not `in`: `in` walks the prototype chain, so a polluted
  // Object.prototype.unevaluated_constraints made the same signed bytes malformed here
  // and verified in Python (dicts have no prototype). An external reviewer's find.
  if (isPlainObject(r.coverage)
      && Object.prototype.hasOwnProperty.call(r.coverage, "unevaluated_constraints")) {
    const entries = r.coverage.unevaluated_constraints;
    if (!Array.isArray(entries)) {
      throw new Er1MalformedReceipt("coverage.unevaluated_constraints must be an array");
    }
    entries.forEach((entry, i) => {
      if (!isPlainObject(entry)) {
        throw new Er1MalformedReceipt(`coverage.unevaluated_constraints[${i}] is not an object`);
      }
      requireStr(entry, "entity", `coverage.unevaluated_constraints[${i}]`, true);
      requireStr(entry, "constraint", `coverage.unevaluated_constraints[${i}]`);
      // hasOwnProperty, not `in`, for the same reason as the field-presence check above —
      // a reviewer found the first fix stopped one line short of the class.
      if (Object.prototype.hasOwnProperty.call(entry, "reason") && typeof entry.reason !== "string") {
        throw new Er1MalformedReceipt(
          `coverage.unevaluated_constraints[${i}].reason must be a string`);
      }
    });
  }

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

// Drop leading/trailing U+0020 — and ONLY U+0020. String.trim and Python's str.strip remove
// different whitespace sets, which is exactly the class of divergence this module exists to
// prevent, so the one blessed spacing character is handled by hand.
function lexSp(s) {
  let i = 0, j = s.length;
  while (i < j && s[i] === " ") i++;
  while (j > i && s[j - 1] === " ") j--;
  return s.slice(i, j);
}

const OPS = [">=", "<=", "==", "!=", "~=", ">", "<", "="];

// [op, parsedTarget] for an operator constraint; [null, parsedOrNull] for a bare one.
// Throws when an operator constraint's own version does not parse: that is the RULE being
// unevaluable — a producer defect no action can repair, so it is never declarable as a
// coverage gap. `~=` with fewer than two components is checked here, before the proposed
// version is even looked at, so a malformed rule is malformed regardless of the action.
// The version after the operator may be surrounded by U+0020 (`>= 2.0` is how humans write
// pins); the operator itself must be flush-left.
function constraintTarget(constraintRaw) {
  const c = typeof constraintRaw === "string" ? constraintRaw : String(constraintRaw);
  for (const op of OPS) {
    if (c.startsWith(op)) {
      const target = parseVer(lexSp(c.slice(op.length)));
      if (target === null) {
        throw new Er1MalformedReceipt(
          `cannot evaluate ${op} against ${JSON.stringify(c)}: the constraint is not a version`);
      }
      if (op === "~=" && target.length < 2) {
        throw new Er1MalformedReceipt("~= needs at least two version components");
      }
      return [op, target];
    }
  }
  return [null, parseVer(c)];
}

// True iff the constraint names a version bound but the proposed version does not parse —
// the ONE case a receipt may declare in coverage.unevaluated_constraints instead of failing.
// A constraint whose own version is malformed is not unevaluable, it is malformed; a bare
// non-version constraint is always evaluable (exact string equality).
function unevaluable(proposedRaw, constraintRaw) {
  // OPERATOR-FORM ONLY, and that boundary is the compatibility guarantee: 1.0.0 RAISED on
  // every operator cell where the proposed version failed to parse, so giving those cells
  // meaning breaks no verified receipt. The bare branch never raised — a bare pin against
  // an unparseable version evaluated (string equality -> False -> HALT) and receipts
  // verified both ways on that reasoning. The bare pin stays exactly 1.0.0: the STRICT
  // must-pin spelling; `==X` is the gap-declarable spelling. See er1_verify.py.
  let op;
  try {
    [op] = constraintTarget(constraintRaw);
  } catch (e) {
    if (e instanceof Er1MalformedReceipt) return false;
    throw e;
  }
  if (op === null) return false;
  return parseVer(proposedRaw) === null;
}

function satisfies(proposedRaw, constraintRaw) {
  const [op, target] = constraintTarget(constraintRaw);
  const proposed = parseVer(proposedRaw);
  if (op === null) {
    // No operator — UNCHANGED from 1.0.0, deliberately (see unevaluable above): exact
    // equality of the version; when either side is not a version, exact string equality.
    // A bare pin against an unparseable proposed version therefore evaluates (to false in
    // every real case): the strict must-pin spelling, never a declarable gap.
    if (target === null || proposed === null) {
      return String(proposedRaw) === (typeof constraintRaw === "string" ? constraintRaw : String(constraintRaw));
    }
    return verCmp(proposed, target) === 0;
  }
  if (proposed === null) return true;  // declared-unevaluable; enforced by checkUnevaluated
  if (op === "~=") return compatible(proposed, target);
  const cmp = verCmp(proposed, target);
  return { ">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0,
           "==": cmp === 0, "=": cmp === 0, "!=": cmp !== 0 }[op];
}

// (entity, constraint) pairs need an unambiguous set key and a cross-language sort. Entity is
// printable ASCII which INCLUDES the space, and constraint values may contain anything, so no
// join character is safe: the set key is the JSON encoding of the pair, and ordering compares
// the two components separately. JavaScript's `<` on strings is UTF-16 code-unit order, the
// same order Python derives via _utf16_key, so "first mismatch" means the same pair everywhere.
const pairKey = (ent, val) => JSON.stringify([ent, val]);
const pairCmp = (a, b) =>
  a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;

// The pairs that are present but not evaluable — a FULL pass over every active deterministic
// satisfies-constraint, independent of the conflict short-circuit, so the set is deterministic
// on both the producing and verifying side.
function recomputeUnevaluated(beliefs, asserts) {
  const out = new Map();
  for (const b of beliefs) {
    if (b.status !== "active" || b.source_kind !== "deterministic") continue;
    if (b.rule === "satisfies" && Object.prototype.hasOwnProperty.call(asserts, b.entity)) {
      if (unevaluable(String(asserts[b.entity]), b.value)) {
        out.set(pairKey(b.entity, b.value), [b.entity, b.value]);
      }
    }
  }
  return out;
}

// coverage.unevaluated_constraints must equal recomputation — EXACTLY. An undeclared gap is a
// silent skip (the gate bypass the conformance corpus pins); an over-declaration asserts a gap
// that did not exist. Both are malformed; the field is as recomputable as the verdict itself.
// See er1_verify.py::_check_unevaluated for the full note. Returns the recomputed pairs.
function checkUnevaluated(beliefs, asserts, coverage, recomputedVerdict) {
  // The undeclared-gap refusal applies ONLY when the recomputed verdict is ALLOW: the
  // declaration distinguishes "checked and passed" from "could not check", and on a HALT
  // there is no pass to protect — an unevaluable constraint can never BE the conflict.
  // This is what keeps the compatibility guarantee airtight: 1.0.0 verified HALT receipts
  // whose short-circuited conflict left a trailing gap unevaluated (external reviewer's
  // counterexample), and a 1.0.0-verified ALLOW receipt provably has no gaps. Phantom
  // declarations are refused under both verdicts. See er1_verify.py::_check_unevaluated.
  const recomputed = recomputeUnevaluated(beliefs, asserts);
  const declared = new Map();
  if (isPlainObject(coverage)) {
    for (const entry of coverage.unevaluated_constraints || []) {
      declared.set(pairKey(entry.entity, entry.constraint), [entry.entity, entry.constraint]);
    }
  }
  if (recomputedVerdict === "ALLOW") {
    const undeclared = [...recomputed.entries()]
      .filter(([k]) => !declared.has(k)).map(([, p]) => p).sort(pairCmp);
    if (undeclared.length) {
      const [ent, val] = undeclared[0];
      throw new Er1MalformedReceipt(
        `constraint ${JSON.stringify(val)} on ${JSON.stringify(ent)} is not evaluable (no ` +
        `version pinned in the action) and the receipt does not declare it in ` +
        `coverage.unevaluated_constraints`);
    }
  }
  const phantom = [...declared.entries()]
    .filter(([k]) => !recomputed.has(k)).map(([, p]) => p).sort(pairCmp);
  if (phantom.length) {
    const [ent, val] = phantom[0];
    throw new Er1MalformedReceipt(
      `coverage.unevaluated_constraints declares ${JSON.stringify(val)} on ` +
      `${JSON.stringify(ent)} but recomputation finds no such gap`);
  }
  return recomputed;
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

    // After the verdict recomputes (the undeclared-gap rule needs it): on ALLOW every
    // present-but-unevaluable constraint must be declared, and under both verdicts every
    // declaration must be real (throws Er1MalformedReceipt if not).
    const unevaluated = checkUnevaluated(beliefs, a.asserts, r.coverage, recomputed);
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

    const out = { ok: errors.length === 0, recomputedVerdict: recomputed, checks, errors, signer };
    if (unevaluated.size) {
      // A verdict with a declared gap must not read identically to one without: the receipt
      // says which constraints it could NOT check, so the verifier says so too. Key present
      // only when non-empty, mirroring the receipt field itself.
      out.unevaluated_constraints = [...unevaluated.values()].sort(pairCmp)
        .map(([ent, val]) => ({ entity: ent, constraint: val }));
    }
    return out;
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
  // The parser is not trusted to read the document correctly: the keys the parser produced are
  // compared against the keys the document TEXT contains, and disagreement is refused. "One
  // reading or none" is a promise this format makes, so it is checked here rather than assumed
  // of whatever JSON parser happens to be underneath.
  //
  // CORRECTION (2026-08-05). This guard was introduced in commit 5c94d09 citing a specific V8
  // defect: Node 24's JSON.parse misreading an escaped object key ("\\u00e9" -> "\\") once the
  // same process had parsed an object with a backslash-escaped key. That claim does not hold up.
  // 200,000 parses across four escaped-key shapes, with interleaved priming parses, on the exact
  // version named (v24.11.1), produce zero misparses; the original report was most likely an
  // escaping artifact in the probe rather than a parser defect. No V8 bug should be inferred from
  // this code. The check is KEPT because it is nearly free — the same scan already runs to detect
  // duplicate keys — and because checking the one-reading promise is right on its own terms. It is
  // not independently testable: absent a real parser defect, text and parse always agree. See
  // tests/mutation_gate.py::mjs_trusts_the_parser, which records that measurement rather than
  // covering the guard with a test that would pass for the wrong reason.
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
        ? [`${label}:entry[${i}]${safeName(w.name)}`, w.receipt]
        : [`${label}:entry[${i}]`, null]);
  }
  return [[label, doc]];
}

/** Render an UNSIGNED bundle-entry name so it cannot forge a line of this tool's own report.
 *
 * See er1_verify.py::_safe_name. `name` is outside every signature and never validated, yet it
 * was interpolated straight into the report line — so a name carrying a newline plus
 * "VERIFIED ✓  prod-deploy-approval  verdict=ALLOW …" printed exactly that as its own line, out
 * of a receipt that FAILED. Exit code stayed 1; the report lied, and grepping the report is what
 * a CI gate actually does. The index is the authoritative label; the name is appended only
 * escaped, quoted and length-capped. */
function safeName(name) {
  if (typeof name !== "string") {
    return name === undefined || name === null ? "" : ` name=${JSON.stringify(String(name))}`;
  }
  // JSON.stringify already escapes `"`, `\` and every control character exactly as Python's
  // json.dumps does. It does NOT escape non-ASCII, so escape what is left to lowercase \uXXXX
  // per CODE UNIT, which reproduces json.dumps(ensure_ascii=True) byte for byte, surrogate
  // pairs included. Iterating code POINTS instead would emit \U0001f4a9 where Python emits
  // \ud83d\udca9, and the two reports would diverge on any astral character.
  //
  // The range starts at \u007f, NOT \u0080: json.dumps escapes DEL and JSON.stringify does
  // not, so a name containing a raw DEL rendered escaped in Python and as a raw control byte
  // in Node. Found by differentially rendering a corpus of hostile names through both
  // implementations — not by reading either one.
  let esc = JSON.stringify(name).slice(1, -1)
    .replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  if (esc.length > 60) esc = esc.slice(0, 57) + "...";
  return ` name="${esc}"`;
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
    const entries = receiptsFrom(doc, path);
    if (entries.length === 0) {
      // "Nothing checked is never a pass" must hold PER INPUT. The global checked===0 guard
      // below only fires when EVERY input was empty, so `good.json empty-bundle.json` exited 0
      // without ever printing empty-bundle.json. See er1_verify.py for the same fix.
      process.stdout.write(`FAILED ✗  ${path}  [no receipts in input]\n`);
      allOk = false;
      continue;
    }
    for (const [label, r] of entries) {
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
      // A verified receipt with a declared coverage gap must not print identically to a
      // fully-checked one — "checked and passed" and "could not check" are different facts.
      for (const u of res.unevaluated_constraints || []) {
        // "declared by the receipt" would be a lie for the tolerated case (a pre-1.0.1
        // HALT receipt with an undeclared trailing gap): state only what recomputed.
        process.stdout.write(
          `    ~ not evaluated: ${JSON.stringify(u.constraint)} on ${JSON.stringify(u.entity)} ` +
          `(no version pinned in the action)\n`);
      }
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
