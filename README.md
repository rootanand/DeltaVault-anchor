# DeltaVault — a published commitment root

**This is a demonstration. Every key here is derived from a fixed one-byte seed,
so anybody can reproduce them and nobody should trust them.** A production
DeltaVault root key is generated in a witnessed ceremony under dual control and
has never existed on a laptop. Nothing in this repository is evidence of
anything.

What it is: a commitment root produced on a laptop, published with the proofs
that connect a single record to it, and a verifier you can read in five minutes
that uses none of DeltaVault's code.

```
git clone https://github.com/rootanand/DeltaVault-anchor
cd DeltaVault-anchor
python3 verify.py
```

Python 3 and the `openssl` command. Nothing else — no pip install, no network,
no account. It recomputes every digest with `hashlib` and checks every signature
by shelling out to OpenSSL, so agreement means two independent implementations
agree rather than that one implementation agrees with itself.

Commitment root:

```
c53877fbd236e423e7abd1d2be17e9cacda8972d17673725d6d620c214ac3dd7
```

[VERIFY.md](VERIFY.md) says what each check establishes and, at greater length,
what it deliberately does not.

## Where this comes from

The DeltaVault engine is a separate, private repository. These artifacts are
generated from it by `cargo xtask publish-demo` and are byte-reproducible: the
same command produces the same bytes, so a change here is a real change in the
engine's output rather than noise.

Published trust artifacts being separate from the engine that makes them is not
an accident of hosting. A verifier needs the artifacts and the specification; it
has never needed our source, and the day it does, the product's central claim
has failed.
