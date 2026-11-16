#!/usr/bin/env python3
"""Check the DeltaVault demonstration commitment root, using none of its code.

Requires Python 3 and OpenSSL 3.5 or later on the path. Nothing else: no pip
install, no network. Run it in the directory holding the published JSON files:

    python3 verify.py

Everything here is written from the DeltaVault annexes and
SPEC-Post-Quantum-Signature-Profiles-v1.0.md, not from the product's source.
Digests are recomputed with hashlib; signatures are checked by shelling out to
OpenSSL. So if this agrees with the published files, two independent
implementations agree. If DeltaVault's code were wrong, this would disagree.

Every DeltaVault signature is a pair: a classical half, Ed25519 or ECDSA, and a
post-quantum half, ML-DSA or SLH-DSA, both over the same pair-bound message. A
pair passes only when both halves pass, and this prints one line per half.

    python3 verify.py --vectors DIR

checks the pair-key vectors and the Wycheproof Ed25519 edge vectors instead,
from a DeltaVault checkout's `fixtures/derived/pair-keys/` and
`fixtures/pq/ed25519-edge/` under DIR, the shared vectors on which this
verifier must agree with DeltaVault's own and with the Challenge Desk's.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

# Spec section 5.1. The label, a zero byte, the suite's name, a zero byte, the
# message. Both halves sign exactly this, so a half cannot be lifted out of a
# pair and replayed under another suite.
PAIR_LABEL = b"DeltaVault-pair-v1"

# Spec section 4.3 and annex A1 section 3: each component's fixed public and
# signature lengths, and the DER prefix that makes its raw public key an SPKI,
# spec section 15.2. ECDSA names the digest its signature is over.
COMPONENTS = {
    "ed25519": (32, 64, "302a300506032b6570032100", None),
    "ecdsa-p256": (65, 64, "3059301306072a8648ce3d020106082a8648ce3d030107034200", "sha256"),
    "ecdsa-p384": (97, 96, "3076301006072a8648ce3d020106052b81040022036200", "sha384"),
    "ml-dsa-65": (1952, 3309, "308207b2300b0609608648016503040312038207a100", None),
    "ml-dsa-87": (2592, 4627, "30820a32300b060960864801650304031303820a2100", None),
    "slh-dsa-sha2-192s": (48, 16224, "3040300b0609608648016503040316033100", None),
    "slh-dsa-sha2-256s": (64, 29792, "3050300b0609608648016503040318034100", None),
}

# The six suites of spec section 4.1, as classical + post-quantum.
SUITES = {
    "ed25519+ml-dsa-65",
    "ecdsa-p256+ml-dsa-65",
    "ecdsa-p384+ml-dsa-87",
    "ed25519+slh-dsa-sha2-192s",
    "ecdsa-p256+slh-dsa-sha2-192s",
    "ecdsa-p384+slh-dsa-sha2-256s",
}

# TDD section 4. Domain-separated tags, so a proof about one kind of tree can
# never be replayed against another.
TAG_RECORD_LEAF = 0x00
TAG_INTERIOR = 0x01
TAG_CKPT_LEAF = 0x03
TAG_LOG_LEAF = 0x04

ok_count = 0
fail_count = 0


def check(label, condition, detail=""):
    global ok_count, fail_count
    if condition:
        ok_count += 1
        print(f"  ok    {label}")
    else:
        fail_count += 1
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
    return condition


def require_openssl():
    """Spec section 15.1: OpenSSL 3.5 is the first to verify ML-DSA and SLH-DSA."""
    message = "OpenSSL 3.5 or later is required to check post-quantum signatures"
    try:
        out = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit(message)
    m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        sys.exit(message)
    print(out.strip())


# ---------------------------------------------------------------------------
# Annex A2, the canonical profile. The whole of it that matters here.
# ---------------------------------------------------------------------------

def canonical(obj) -> bytes:
    """Re-emit a value in the canonical profile.

    Annex A2: keys sorted by UTF-8 byte value, no insignificant whitespace, no
    trailing newline. `sort_keys` sorts by code point, which is the same order
    for the ASCII keys this format uses. There is no number case to handle
    because annex A2 section 4.2 forbids JSON numbers outright: every integer
    is a quoted decimal string.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def load(name):
    raw = pathlib.Path(name).read_bytes()
    obj = json.loads(raw)
    # A published file that is not already canonical would mean the digests
    # taken over it are not reproducible, so this is checked rather than assumed.
    if canonical(obj) != raw:
        print(f"  FAIL  {name} is not in canonical form")
        sys.exit(1)
    return obj


def without(obj, *keys):
    """The signing bytes: the object minus the members that carry signatures."""
    return canonical({k: v for k, v in obj.items() if k not in keys})


# ---------------------------------------------------------------------------
# Ed25519 small-order refusal, spec section 5.2
# ---------------------------------------------------------------------------

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _decode(b: bytes):
    """An Ed25519 point in extended coordinates, or None if it does not decode."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P != 0:
        x = (x * SQRT_M1) % P
        if (v * x * x - u) % P != 0:
            return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def _double(pt):
    x, y, z, _ = pt
    a, b = x * x % P, y * y % P
    c = 2 * z * z % P
    h = (a + b) % P
    e = (h - (x + y) * (x + y)) % P
    g = (a - b) % P
    f = (c + g) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def small_order(b: bytes) -> bool:
    """Whether a 32-byte encoding is a point of order dividing eight, the torsion
    `ed25519-dalek`'s `verify_strict` refuses for keys and for R, spec 5.2."""
    pt = _decode(b)
    if pt is None:
        return False
    for _ in range(3):
        pt = _double(pt)
    x, y, z, _ = pt
    return x % P == 0 and (y - z) % P == 0


# ---------------------------------------------------------------------------
# Signatures, via OpenSSL
# ---------------------------------------------------------------------------

def _der_int(b: bytes) -> bytes:
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def ecdsa_der(rs: bytes) -> bytes:
    """Fixed-width `r || s`, spec section 4.4, as the DER OpenSSL expects."""
    half = len(rs) // 2
    body = _der_int(rs[:half]) + _der_int(rs[half:])
    return b"\x30" + _der_len(len(body)) + body


def verify_half(component: str, key: bytes, message: bytes, sig: bytes) -> bool:
    """One half, by `openssl pkeyutl`. Any failure, including a decode
    failure, is `False` and never an exception that escapes, spec 5.2."""
    try:
        _, _, prefix, digest = COMPONENTS[component]
        if component == "ed25519" and (small_order(key) or small_order(sig[:32])):
            return False
        if digest:
            sig = ecdsa_der(sig)
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "key.der").write_bytes(bytes.fromhex(prefix) + key)
            (d / "msg.bin").write_bytes(message)
            (d / "sig.bin").write_bytes(sig)
            cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(d / "key.der"),
                   "-keyform", "DER", "-rawin", "-in", str(d / "msg.bin"),
                   "-sigfile", str(d / "sig.bin")]
            if digest:
                cmd += ["-digest", digest]
            r = subprocess.run(cmd, capture_output=True, text=True)
        return r.returncode == 0 and "Success" in r.stdout
    except Exception:
        return False


def key_identity(key) -> str:
    """Spec section 4.3: SHA-256 over the suite's name, a zero byte and the
    encoding, so one byte string can never name two keys of different suites."""
    return hashlib.sha256(key["alg"]["sig"].encode() + b"\x00"
                          + bytes.fromhex(key["encoded"])).hexdigest()


def pair(key, message: bytes, sig):
    """Spec section 5.2 exactly: `(classical, pq)` results, or a refusal."""
    if sig["key_id"] != key["key_id"] or sig["alg"] != key["alg"]:
        return "key mismatch"
    if key_identity(key) != key["key_id"]:
        return "key identity"
    suite = key["alg"]["sig"]
    if suite not in SUITES:
        return f"unknown suite {suite!r}"
    classical, pq = suite.split("+")
    k = bytes.fromhex(key["encoded"])
    s = bytes.fromhex(sig["value"])
    if len(k) != COMPONENTS[classical][0] + COMPONENTS[pq][0]:
        return "key length"
    if len(s) != COMPONENTS[classical][1] + COMPONENTS[pq][1]:
        return "signature length"
    kc, sc = COMPONENTS[classical][0], COMPONENTS[classical][1]
    m_pair = PAIR_LABEL + b"\x00" + suite.encode() + b"\x00" + message
    return (verify_half(classical, k[:kc], m_pair, s[:sc]),
            verify_half(pq, k[kc:], m_pair, s[sc:]))


def verify_sig(label, key, message: bytes, sig) -> bool:
    """Spec section 15.1: the whole key and signature objects, one line per
    half, and a pass only when both halves pass."""
    result = pair(key, message, sig)
    if isinstance(result, str):
        return check(f"{label}: refused, {result}", False)
    classical, pq = key["alg"]["sig"].split("+")
    c = check(f"{label}, {classical} half", result[0])
    q = check(f"{label}, {pq} half", result[1])
    return c and q


# ---------------------------------------------------------------------------
# Merkle, TDD section 4
# ---------------------------------------------------------------------------

def interior(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes([TAG_INTERIOR]) + left + right).digest()


def record_leaf(shard: int, seq: int, derived: bytes) -> bytes:
    return hashlib.sha256(bytes([TAG_RECORD_LEAF])
                          + shard.to_bytes(4, "big")
                          + seq.to_bytes(8, "big")
                          + derived).digest()


def replay_path(leaf: bytes, proof) -> bytes:
    """Walk an inclusion path from the leaf to a root.

    There is no promotion case here. An odd node is promoted unchanged when a
    tree is *built*, so it contributes no step to a path and a verifier never
    has to know about it.
    """
    node = leaf
    for step in proof["path"]:
        sibling = bytes.fromhex(step["sibling"])
        # Annex A1 types this as the string "true" or "false", not a JSON
        # boolean. The two are different bytes and therefore different digests.
        if step["sibling_on_left"] == "true":
            node = interior(sibling, node)
        else:
            node = interior(node, sibling)
    return node


def check_proof(label, doc):
    leaf = bytes.fromhex(doc["leaf"])
    computed = replay_path(leaf, doc["proof"])
    return check(label, computed.hex() == doc["expected_root"],
                 f"recomputed {computed.hex()}, published {doc['expected_root']}")


# ---------------------------------------------------------------------------
# The shared vectors, spec section 16.5
# ---------------------------------------------------------------------------

def vectors(base: pathlib.Path) -> int:
    print("\n1. The pair-key vectors, every suite")
    for path in sorted((base / "fixtures/derived/pair-keys").glob("*.json")):
        v = json.loads(path.read_bytes())
        if v.get("kind") != "pair":
            continue
        message = bytes.fromhex(v["message"])
        built = (PAIR_LABEL + b"\x00" + v["suite"].encode() + b"\x00" + message).hex()
        check(f"{v['suite']}: the pair-bound message rebuilds", built == v["m_pair"])
        check(f"{v['suite']}: the key owns its identity", key_identity(v["key"]) == v["key_id"])
        verify_sig(v["suite"], v["key"], message, v["signature"])
        # A pair with one byte of its post-quantum half flipped fails that half.
        bad = dict(v["signature"])
        value = bytearray.fromhex(bad["value"])
        value[-1] ^= 1
        bad["value"] = value.hex()
        result = pair(v["key"], message, bad)
        check(f"{v['suite']}: a flipped post-quantum byte fails that half only",
              result == (True, False), f"got {result}")

    print("\n2. The Wycheproof Ed25519 edge vectors")
    # Spec section 5.2: the Rust verifier is normative. It refuses the eight
    # small-order keys and accepts the twenty-one mixed-order ones of the
    # `acceptable` set, and every `valid` and `invalid` vector as labelled.
    suite = json.loads((base / "fixtures/pq/ed25519-edge/ed25519_test.json").read_bytes())
    agree = disagree = skipped = 0
    for group in suite["testGroups"]:
        pk = bytes.fromhex(group["pk"])
        for t in group["tests"]:
            # OpenSSL 3.5's command line cannot verify an empty message: both
            # `pkeyutl -rawin` and `dgst` refuse a zero-byte input before they
            # look at the signature. No DeltaVault message is ever empty, since
            # the pair label prefixes every one, so these vectors say nothing
            # about this verifier and are counted rather than guessed at.
            if not t["msg"]:
                skipped += 1
                continue
            want = t["result"]
            if want == "acceptable":
                want = "invalid" if "SmallOrderPublicKey" in t["flags"] else "valid"
            sig = bytes.fromhex(t["sig"])
            got = (len(pk) == 32 and len(sig) == 64
                   and verify_half("ed25519", pk, bytes.fromhex(t["msg"]), sig))
            if got == (want == "valid"):
                agree += 1
            else:
                disagree += 1
                print(f"  FAIL  tcId {t['tcId']}: expected {want}, OpenSSL said {got}")
    check(f"all {agree + disagree} Wycheproof vectors with a message decided as the Rust "
          f"verifier decides", disagree == 0, f"{disagree} disagreed")
    print(f"  skip  {skipped} with an empty message, which the OpenSSL command line cannot verify")
    print(f"\n{ok_count} checks passed, {fail_count} failed")
    return 1 if fail_count else 0


# ---------------------------------------------------------------------------

def main():
    require_openssl()
    if len(sys.argv) == 3 and sys.argv[1] == "--vectors":
        return vectors(pathlib.Path(sys.argv[2]))

    root = load("root.json")
    chain = load("continuity.json")
    batch = load("batch.json")
    ckpt = load("checkpoint.json")
    head = load("log-head.json")
    witness = load("log-witness.json")
    print(f"profile: {root['profile']}")

    print("\n1. The root file stands on its own")
    signer = next((k for k in root["roots"] if k["key_id"] == root["signature"]["key_id"]), None)
    if not check("the file is signed by a key it publishes", signer is not None):
        sys.exit(1)
    check("that key owns its stated identity", key_identity(signer) == signer["key_id"])
    verify_sig("the root file's self-signature",
               signer, without(root, "signature", "cross_signature"), root["signature"])

    print("\n2. The batch signing key chains back to the published root")
    # Annex A13 section 5, step two. Walk from the key that signed the batch to
    # a key the root file carries.
    known = {k["key_id"]: k for k in root["roots"]}
    for i, record in enumerate(chain):
        predecessor = known.get(record["predecessor_key_id"])
        if not check(f"continuity[{i}] names a key already trusted", predecessor is not None):
            break
        # The signature covers the record minus itself, so sealed_at and anchor
        # are authenticated too and a rotation's stated time cannot be restated.
        if verify_sig(f"continuity[{i}] is signed by its predecessor",
                      predecessor, without(record, "signature"), record["signature"]):
            successor = record["successor_key"]
            check(f"continuity[{i}]'s successor owns its identity",
                  key_identity(successor) == successor["key_id"])
            known[successor["key_id"]] = successor

    batch_signer = known.get(batch["signature"]["key_id"])
    check("the batch's signing key is reachable from a published root",
          batch_signer is not None)

    print("\n3. The commitment root")
    if batch_signer:
        verify_sig("the batch commitment's signature",
                   batch_signer, without(batch, "signature"), batch["signature"])
    ckpt_signer = known.get(ckpt["operator_sig"]["key_id"])
    if check("the checkpoint's signing key is reachable too", ckpt_signer is not None):
        # log_witness is stripped: it is attached by the log after the operator
        # signs, so including it would make the operator's signature
        # unverifiable the moment the log answered.
        verify_sig("the checkpoint's operator signature",
                   ckpt_signer, without(ckpt, "operator_sig", "log_witness"),
                   ckpt["operator_sig"])

    print("\n4. The proofs")
    record_doc = load("record-inclusion.json")
    # Recompute the leaf from the record's own coordinates rather than trusting
    # the published leaf digest, or the proof would only prove something about a
    # number we were handed.
    recomputed_leaf = record_leaf(int(batch["shard"]), 2,
                                  hashlib.sha256(b"record-2").digest())
    check("the record leaf recomputes from shard, sequence and content digest",
          recomputed_leaf.hex() == record_doc["leaf"],
          f"recomputed {recomputed_leaf.hex()}")
    check_proof("the record's inclusion proof reaches the batch root", record_doc)
    check("and that batch root is the one the batch commitment states",
          record_doc["expected_root"] == batch["root"])

    membership = load("checkpoint-membership.json")
    expected_ckpt_leaf = hashlib.sha256(
        bytes([TAG_CKPT_LEAF]) + bytes.fromhex(batch["root"])).digest()
    check("the checkpoint leaf is the batch root under the checkpoint tag",
          expected_ckpt_leaf.hex() == membership["leaf"])
    check_proof("the checkpoint membership proof reaches the commitment root", membership)
    check("and that root is the one the checkpoint states",
          membership["expected_root"] == ckpt["ckpt_root"])

    print("\n5. The anchor log witnessed it")
    check("the log key owns its stated identity",
          key_identity(root["log_key"]) == root["log_key"]["key_id"])
    verify_sig("the log head's signature",
               root["log_key"], without(head, "signature"), head["signature"])
    log_doc = load("log-inclusion.json")
    expected_log_leaf = hashlib.sha256(
        bytes([TAG_LOG_LEAF]) + bytes.fromhex(ckpt["ckpt_root"])).digest()
    check("the log leaf is the commitment root under the log tag",
          expected_log_leaf.hex() == log_doc["leaf"])
    check_proof("the commitment root is included in the log", log_doc)
    check("at the root the signed head states", log_doc["expected_root"] == head["root"])
    verify_sig("the log's own witness statement",
               root["log_key"], without(witness, "signature"), witness["signature"])
    check("the witness names the same commitment root",
          witness["ckpt_root"] == ckpt["ckpt_root"])

    print(f"\n{ok_count} checks passed, {fail_count} failed")
    if fail_count:
        return 1
    print("\nEvery digest above was recomputed here and both halves of every signature")
    print("were checked by OpenSSL. None of DeltaVault's code ran. See VERIFY.md for")
    print("what this does and does not establish.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
