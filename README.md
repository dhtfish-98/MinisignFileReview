# MinisignFileReview

Minisign prehashed ED detached file and trusted-comment signatures, explicit pinned public key; legacy Ed only with explicit opt-in.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `minisign-file-review request.json` or pipe JSON to `minisign-file-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Maximum file size 16 MiB; no signing or private-key operations; verified comments represented by digest to avoid accidental disclosure.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `file` is an authorized local regular file (maximum 16 MiB), `public_key` is an independently pinned Minisign public-key record, and `signature` is the four-line detached signature text. Only the prehashed ED mode is enabled by default; legacy Ed requires explicit boolean `allow_legacy=true`. Both the file signature and global signature over the signature bytes plus UTF-8 trusted comment must verify. Public key IDs must match. Output contains hashes rather than file bytes or comment text.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; parsed floating-point overflow is rejected as nonfinite; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
minisign-file-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.

## File input platform contract

Regular-file input and file-based CLI requests require usable `os.O_NOFOLLOW` and `os.O_NONBLOCK` capabilities. Missing capabilities produce a controlled incomplete FAIL; there is no fallback that follows the final-component symlink or blocks on a FIFO. macOS and Linux CI have been exercised. Native Windows file-input behavior remains unverified.

## Re-audited input semantics

The optional allow_legacy field is always validated as a JSON boolean, including prehashed ED mode where it does not change signature processing.
