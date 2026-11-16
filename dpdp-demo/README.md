# DeltaVault DPDP demo, published checkpoints

The Fiduciary Desk of the DPDP demo publishes each checkpoint root here on its live path. `checkpoint.json` is the latest, `checkpoints/` holds every one by root, and `index.html` lists them for a reader.

**Restarted under the post-quantum format.** The 21 checkpoints published here before were signed with Ed25519 demonstration keys in the old format. Under DeltaVault's post-quantum signature profiles every signature is a pair of a classical and a post-quantum signature, so those were removed and this feed starts again from empty, rather than leaving a mixed history that would only confuse a reader. They were never evidence of anything; their history is in this repository's git log.

This is the operator's own feed, operator-local by annex A1 section 7.2, and it is separate from the DeltaVault demonstration set at the repository root, whose `verify.py` is bound to that set. Nothing here is evidence of anything, every key is a demo key.
