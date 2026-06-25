#!/usr/bin/env node
// ER1 — standalone offline verifier, JavaScript reference implementation.
//
// A SECOND-LANGUAGE verifier for the Epistemic Receipt (ER1) format. It depends on nothing but
// Node's built-in `node:crypto` — no npm install, no network, no engine code. It reproduces
// `er1_verify.py` byte-for-byte: the same RFC 8785–compatible canonical JSON, the same Ed25519
// check over the SHA-256 digest, the same constraint predicate and verdict recomputation. Two
// independent implementations agreeing on the same signed bytes is what makes ER1 a STANDARD, not
// a log: anyone can re-derive the verdict in their own stack and get the identical answer.
//
//     node er1_verify.mjs receipt.json [...]        # verify receipt file(s)
//     node er1_verify.mjs golden_vectors.json       # self-test the published vectors
//
// What it certifies: the verdict correctly follows from the recorded, signed pre-state — NOT the
// empirical truth of the constraints ("garbage in, certified garbage out").
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

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
    const keys = Object.keys(v).sort(); // default UTF-16 code-unit order == python _utf16_key
    return "{" + keys.map((k) => escapeString(k) + ":" + canon(v[k])).join(",") + "}";
  }
  throw new TypeError("cannot canonicalize " + typeof v);
}

const canonicalBytes = (v) => Buffer.from(canon(v), "utf8");
const sha256Hex = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");

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
export const receiptHash = (r) => sha256Hex(canonicalBytes(body(r)));

function verifySignature(r) {
  const sb = r.signature;
  if (!sb || sb.algorithm !== "ed25519") return false;
  try {
    // The signed message is the SHA-256 digest of the canonical body (matches er1_verify.py and the
    // signer; pinned by golden_vectors.json). edVerify(null, digest, ...) is plain Ed25519 over that
    // 32-byte message — identical to the Python side, as the golden vectors prove.
    const digest = createHash("sha256").update(canonicalBytes(body(r))).digest();
    const pub = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: String(sb.public_key).replace(/=+$/, "") },
      format: "jwk",
    });
    return edVerify(null, digest, pub, Buffer.from(sb.signature, "base64url"));
  } catch {
    return false;
  }
}

export function verify(r) {
  const errors = [], checks = {};

  checks.signature = verifySignature(r);
  if (!checks.signature) errors.push("signature: invalid or missing");

  const a = r.action ?? {};
  const expect = sha256Hex(canonicalBytes(
    { tool: a.tool ?? "", asserts: a.asserts ?? {}, resource: a.resource ?? "" }));
  checks.binding = (r.action_binding ?? {}).args_hash === expect;
  if (!checks.binding) errors.push("action_binding: args_hash mismatch");

  const beliefs = r.beliefs ?? [];
  checks.state_root = r.pre_state_root === sha256Hex(canonicalBytes(beliefs));
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

// ── CLI ──
function receiptsFrom(doc) {
  // A golden_vectors bundle wraps each receipt as {name, receipt, ...}; a bare receipt has `decision`.
  if (doc && Array.isArray(doc.receipts)) return doc.receipts.map((w) => [w.name, w.receipt]);
  return [[null, doc]];
}

function main(argv) {
  if (argv.length === 0) {
    process.stderr.write("usage: node er1_verify.mjs <receipt.json | golden_vectors.json> [...]\n");
    return 2;
  }
  let allOk = true;
  for (const path of argv) {
    const doc = JSON.parse(readFileSync(path, "utf8"));
    for (const [name, r] of receiptsFrom(doc)) {
      const res = verify(r);
      const label = name ? `${path}:${name}` : path;
      const status = res.ok ? "VERIFIED ✓" : "FAILED ✗";
      const v = (r.decision ?? {}).verdict;
      process.stdout.write(`${status}  ${label}  verdict=${v} (recomputed ${res.recomputedVerdict})  hash=${receiptHash(r).slice(0, 18)}…\n`);
      for (const e of res.errors) process.stdout.write(`    ! ${e}\n`);
      allOk = allOk && res.ok;
    }
  }
  return allOk ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
