# Checking this yourself

```
python3 verify.py
```

Python 3 and the `openssl` command. No pip install, no network, no account.

`verify.py` recomputes every digest with `hashlib` and checks every signature by
shelling out to OpenSSL. None of DeltaVault's code runs. If it agrees with these
files, two independent implementations agree.

---

## What each step establishes

**1. The root file stands on its own.** It is signed by a key it publishes, and
that key's stated identity really is the digest of its own bytes. A file signed
by a key it does not carry would be asking to be trusted on the strength of a
name.

**2. The batch signing key chains back to that root.** The key that signed the
commitment is not a root key. A continuity record binds it under the root's
signature, and that signature covers the whole record — including *when* the
rotation happened and *which anchor* witnessed it — so a rotation's stated time
cannot be restated later by anyone holding the file.

**3. The commitment root is signed by a key that chain reaches.** Both the batch
commitment and the checkpoint. Note the checkpoint's signature is taken over the
checkpoint *without* the log's witness, because the witness is attached
afterwards by a different party.

**4. The proofs.** A record's inclusion proof reaches the batch root, and the
batch root's membership proof reaches the commitment root. The record's leaf is
recomputed from its shard, sequence number and content digest rather than taken
from the file — otherwise the proof would only prove something about a number
you were handed.

**5. The anchor log witnessed it.** The commitment root is included in the log's
tree at the size its signed head states, and the log's own witness statement
names the same root.

## What this does not establish

**Nothing about the content of any record.** These are digests. A digest proves
that *something* with those bytes existed and was committed at a position; it
says nothing about what that something was, and nothing here discloses it.

**Nothing about time.** The batch says `local-attested`, which is this format's
way of saying the operator's own clock and nothing more. There is no RFC 3161
timestamp token in this set, so no independent party has attested *when* any of
this happened. Real deployments carry one; sprint 2 builds that path.

**Nothing about independence.** The anchor log that witnessed this checkpoint ran
on the same laptop as the signer. The assurance record says so —
`operator-local`, not `independent` — and that is deliberate. An operator's own
log corroborates; it does not testify. Marking it `independent` would be exactly
the inflation the format exists to prevent, and it would have been invisible to
you.

**And nothing at all about trust.** Every key here is derived from a fixed
one-byte seed committed to a source repository. Anybody can reproduce them and
therefore anybody can forge everything in this directory. It is a demonstration
of a *format* and a *procedure*, not evidence.

## Why the checks are worth this much prose

The claim DeltaVault makes is that evidence survives the vendor. That claim is
only worth anything if somebody with no relationship to the vendor can check the
evidence, using tools they already have, from a written specification, years
later. A verifier you cannot re-implement in an afternoon is one nobody will
re-implement, and unchecked evidence is not evidence.

So: two hundred lines, two dependencies both of which predate the product, and a
list above of what it refuses to claim.
