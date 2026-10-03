# Origin and implementation scope

The new independent implementation is authored by **dhtfish98** (package version **0.1.2**). Upstream works retain their original attribution and license notices in this document and `UPSTREAM_LICENSE`.

MinisignFileReview independently implements this selected scope: Minisign prehashed ED detached file and trusted-comment signatures, explicit pinned public key; legacy Ed only with explicit opt-in.

The research source is [jedisct1/minisign](https://github.com/jedisct1/minisign) at fixed commit `4ade1121ba8b65e0e7568a5b411aa4733284e8a8`. Source archive SHA-256: `bcc633af88c07bff7738776a8d1a7c7d4c4c6669084f66150e0ca0e9eb42548d`. Its license is ISC; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [src/minisign.c](https://github.com/jedisct1/minisign/blob/4ade1121ba8b65e0e7568a5b411aa4733284e8a8/src/minisign.c) — SHA-256 `ebff7824247282cfc7ed5ba7e09713cf667a0d633680dd93ce6856db5b7c3263`.
- [src/helpers.c](https://github.com/jedisct1/minisign/blob/4ade1121ba8b65e0e7568a5b411aa4733284e8a8/src/helpers.c) — SHA-256 `e5f079150e91ee690656c176dde284ad58c4d73ad9525532a59614a0c52d8d81`.
- [README.md](https://github.com/jedisct1/minisign/blob/4ade1121ba8b65e0e7568a5b411aa4733284e8a8/README.md) — SHA-256 `652c531dad34d7972ed9e4353f9bd0f8c6b76c119b49b4e7f65a7488d0d53576`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on detached signature wire format, prehashed ED and trusted-comment signature inputs. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `file` is an authorized local regular file (maximum 16 MiB), `public_key` is an independently pinned Minisign public-key record, and `signature` is the four-line detached signature text. Only the prehashed ED mode is enabled by default; legacy Ed requires explicit boolean `allow_legacy=true`. Both the file signature and global signature over the signature bytes plus UTF-8 trusted comment must verify. Public key IDs must match. Output contains hashes rather than file bytes or comment text.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.

## Re-audited supported semantics

The optional allow_legacy field is always validated as a JSON boolean, including prehashed ED mode where it does not change signature processing.
