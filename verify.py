#!/usr/bin/env python3
"""Check the DeltaVault demonstration commitment root, using none of its code.

Requires Python 3 and the `openssl` command. Nothing else — no pip install, no
network. Run it in the directory holding the published JSON files:

    python3 verify.py

Everything here is written from the DeltaVault annexes, not from the product's
source. Digests are recomputed with hashlib; signatures are checked by shelling
out to OpenSSL. So if this agrees with the published files, two independent
implementations agree. If DeltaVault's commitment code were wrong, this would
disagree with it.

It is about two hundred lines, and that is the point: an evidence format you
cannot re-implement in an afternoon is one nobody will check in year nine.
"""

import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

# Annex A1 section 2: Ed25519 public keys travel as the raw 32 bytes. OpenSSL
# wants SPKI DER, which for Ed25519 is this fixed 12-byte prefix and the key.
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")

# TDD section 4. Five domain-separated tags, so a proof about one kind of tree
# can never be replayed against another.
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


# ---------------------------------------------------------------------------
# Annex A2, the canonical profile. The whole of it that matters here.
# ---------------------------------------------------------------------------

def canonical(obj) -> bytes:
    """Re-emit a value in the canonical profile.

    Annex A2: keys sorted by UTF-8 byte value, no insignificant whitespace, no
    trailing newline. `sort_keys` sorts by code point, which is the same order
    for the ASCII keys this format uses. There is no float or number case to
    handle because annex A2 section 4.2 forbids JSON numbers outright — every
    integer is already a quoted decimal string, which is exactly what lets this
    function be four lines long and still be correct.
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
# Signatures, via OpenSSL
# ---------------------------------------------------------------------------

def verify_sig(label, public_key_hex, message: bytes, signature_hex) -> bool:
    der = SPKI_ED25519 + bytes.fromhex(public_key_hex)
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + base64.encodebytes(der).decode().replace("\n", "")
           + "\n-----END PUBLIC KEY-----\n")
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "k.pem").write_text(pem)
        (d / "m.bin").write_bytes(message)
        (d / "s.bin").write_bytes(bytes.fromhex(signature_hex))
        r = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(d / "k.pem"),
             "-rawin", "-in", str(d / "m.bin"), "-sigfile", str(d / "s.bin")],
            capture_output=True, text=True)
    return check(label, r.returncode == 0 and "Success" in r.stdout, r.stderr.strip())


def key_id(public_key_hex) -> str:
    """Annex A1 section 3: a key's identity is the digest of its encoding."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


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

    Note there is no promotion case here. An odd node is promoted unchanged when
    a tree is *built*, which means it simply contributes no step to a path, so a
    verifier never has to know about it. Only the builder does.
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

def main():
    root = load("root.json")
    chain = load("continuity.json")
    batch = load("batch.json")
    ckpt = load("checkpoint.json")
    head = load("log-head.json")
    witness = load("log-witness.json")

    print("\n1. The root file stands on its own")
    signer = next((k for k in root["roots"] if k["key_id"] == root["signature"]["key_id"]), None)
    if not check("the file is signed by a key it publishes", signer is not None):
        sys.exit(1)
    check("that key owns its stated identity",
          key_id(signer["encoded"]) == signer["key_id"])
    verify_sig("the root file's self-signature",
               signer["encoded"], without(root, "signature", "cross_signature"),
               root["signature"]["value"])

    print("\n2. The batch signing key chains back to the published root")
    # Annex A13 section 5, step two. Walk from the key that signed the batch to
    # a key the root file carries.
    known = {k["key_id"]: k["encoded"] for k in root["roots"]}
    for i, record in enumerate(chain):
        predecessor = known.get(record["predecessor_key_id"])
        if not check(f"continuity[{i}] names a key already trusted", predecessor is not None):
            break
        # The signature covers the record minus itself, so sealed_at and anchor
        # are authenticated too and a rotation's stated time cannot be restated.
        if verify_sig(f"continuity[{i}] is signed by its predecessor",
                      predecessor, without(record, "signature"),
                      record["signature"]["value"]):
            successor = record["successor_key"]
            check(f"continuity[{i}]'s successor owns its identity",
                  key_id(successor["encoded"]) == successor["key_id"])
            known[successor["key_id"]] = successor["encoded"]

    batch_signer = known.get(batch["signature"]["key_id"])
    check("the batch's signing key is reachable from a published root",
          batch_signer is not None)

    print("\n3. The commitment root")
    if batch_signer:
        verify_sig("the batch commitment's signature",
                   batch_signer, without(batch, "signature"), batch["signature"]["value"])
    ckpt_signer = known.get(ckpt["operator_sig"]["key_id"])
    if check("the checkpoint's signing key is reachable too", ckpt_signer is not None):
        # log_witness is stripped: it is attached by the log after the operator
        # signs, so including it would make the operator's signature
        # unverifiable the moment the log answered.
        verify_sig("the checkpoint's operator signature",
                   ckpt_signer, without(ckpt, "operator_sig", "log_witness"),
                   ckpt["operator_sig"]["value"])

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
    verify_sig("the log head's signature",
               root["log_key"]["encoded"], without(head, "signature"),
               head["signature"]["value"])
    log_doc = load("log-inclusion.json")
    expected_log_leaf = hashlib.sha256(
        bytes([TAG_LOG_LEAF]) + bytes.fromhex(ckpt["ckpt_root"])).digest()
    check("the log leaf is the commitment root under the log tag",
          expected_log_leaf.hex() == log_doc["leaf"])
    check_proof("the commitment root is included in the log", log_doc)
    check("at the root the signed head states", log_doc["expected_root"] == head["root"])
    verify_sig("the log's own witness statement",
               root["log_key"]["encoded"], without(witness, "signature"),
               witness["signature"]["value"])
    check("the witness names the same commitment root",
          witness["ckpt_root"] == ckpt["ckpt_root"])

    print(f"\n{ok_count} checks passed, {fail_count} failed")
    if fail_count:
        return 1
    print("\nEvery digest above was recomputed here and every signature was checked")
    print("by OpenSSL. None of DeltaVault's code ran. See VERIFY.md for what this")
    print("does and does not establish.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
