# Test vectors (`PQC/Data`)

The Project Wycheproof vectors are copied next to the test assembly into
`PQC/Data`; nothing in this folder but this README is committed. The NIST
(CAVP and ACVP) vectors are downloaded too, by a separate mechanism: see
`../../Nist/README.md`.

## Project Wycheproof vectors — downloaded, not committed

The `wycheproof_*.json` files are **not checked in** and never appear in this
folder. They are downloaded, unmodified, from the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) project (`testvectors_v1/`)
by the `FetchWycheproofVectors` MSBuild target in `cas-dotnet-sdk-tests.csproj`,
which runs automatically on every `dotnet build` / `dotnet test` — locally and in
CI — into `obj/<config>/<tfm>/wycheproof/`, and is copied next to the test
assembly as `PQC/Data/<local name>`. This matches the
[cas-typescript-sdk](https://github.com/Cryptographic-API-Services/cas-typescript-sdk)
approach, so the vectors never have to be manually re-committed. They come
from a pinned commit and are checked against pinned SHA-256 digests (below).

Each target framework gets its own download folder because a plain
`dotnet test` builds all five frameworks in parallel; a shared folder makes
those builds collide ("the file is being used by another process").

| Local file | Upstream file | Exercised by |
| --- | --- | --- |
| `wycheproof_aes_gcm.json` | `aes_gcm_test.json` | `Wycheproof/AesGcmWycheproofTests.cs` |
| `wycheproof_ed25519.json` | `ed25519_test.json` | `Wycheproof/Ed25519WycheproofTests.cs` (`VerifyWithPublicKeyBytes` on every key; `VerifyBytes` too on the two keys with published seeds) |
| `wycheproof_x25519.json` | `x25519_test.json` | `Wycheproof/X25519WycheproofTests.cs` |
| `wycheproof_hmac_sha256.json` | `hmac_sha256_test.json` | `Wycheproof/HmacWycheproofTests.cs` |
| `wycheproof_mlkem_1024_decaps.json` | `mlkem_1024_semi_expanded_decaps_test.json` | `MLKEMWrapperTests.WycheproofDecapsulationVectors` |
| `wycheproof_mldsa_65_sign.json` | `mldsa_65_sign_seed_test.json` | `MLDSAWrapperTests.WycheproofSigningVectors` |
| `wycheproof_mldsa_65_verify.json` | `mldsa_65_verify_test.json` | `MLDSAWrapperTests.WycheproofSignatureVerificationVectors` |
| `wycheproof_rsa_pkcs1_{2048,3072,4096}_sha256.json` | `rsa_signature_{2048,3072,4096}_sha256_test.json` | `Wycheproof/RsaWycheproofTests.cs` (`RSAWrapper.Verify`, RS256) |
| `wycheproof_rsa_pss_{2048,3072,4096}_sha256_mgf1_32.json` | `rsa_pss_{2048,3072,4096}_sha256_mgf1_32_test.json` | `Wycheproof/RsaWycheproofTests.cs` (`RSAWrapper.VerifyPss`, PS256) |

- **Pinned and checked:** the target downloads from a fixed commit,
  `WycheproofCommit` in `cas-dotnet-sdk-tests.csproj` (logged as `Fetching
  Wycheproof vectors from C2SP/wycheproof@<sha>`), and every build checks each
  file against the SHA-256 in its `WycheproofVector` item's `Sha256` metadata. A
  mismatch fails the build and deletes the cached copy. Files are re-downloaded
  only when the ref changes; otherwise the build logs `Wycheproof vectors
  already at ...`.
- **Try another ref:** pass a branch, tag or commit SHA:

  ```bash
  dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 -p:WycheproofRef=main
  ```

  or set the `WYCHEPROOF_REF` environment variable. A branch or tag is resolved
  to a SHA with `git ls-remote`. Files from any commit other than
  `WycheproofCommit` can't be checked: the build warns and logs each file's
  digest as `<local name>: Sha256="<hex>"`.
- **Refreshing the pin:** run the command above with `-p:WycheproofRef=main`,
  review the upstream changes, and if the tests pass, set `WycheproofCommit` to
  the logged SHA and copy the logged digests into the `Sha256` metadata (case
  doesn't matter). Do it in its own PR.
- **Offline:** if the ref can't be resolved (no network, or `git` not on PATH)
  and the vectors were downloaded before, they are reused with a build warning.
  `-p:FetchWycheproofVectors=false` skips the network entirely.
- **New failures:** with the pin, upstream changes can't break the tests. A
  Wycheproof test that fails only with a newer ref usually means upstream added
  a case the SDK (or the test) doesn't handle yet.
- **Adding a file:** add one `WycheproofVector` item to
  `cas-dotnet-sdk-tests.csproj` (local name as `Include`, upstream name as
  `Upstream`, its SHA-256 at `WycheproofCommit` as `Sha256`), add a row above,
  and load it with `PqcVectorData.Load(...)`.
- **Result semantics:** Wycheproof `result` is three-way. Tests assert `valid` and
  `invalid`; `acceptable` is allowed to go either way unless the algorithm
  defines a single correct output (X25519).

Wycheproof is licensed under the Apache License 2.0; see
<https://github.com/C2SP/wycheproof/blob/main/LICENSE>.

### Skipped vectors, and why

Tests skip only what the SDK's public API cannot express; skips are counted and
reported in the failure message.

- **AES-GCM with non-96-bit IVs, non-128-bit tags, or AES-192 keys** — the API
  takes a 96-bit nonce, appends a 128-bit tag, and exposes only AES-128/256.
  `AesGcmWycheproofTests` also still skips vectors with AAD: it predates the
  `aad` overloads (which the NIST tests exercise).
- **Ed25519, RSA and HMAC vectors with an empty message (or empty HMAC key)** — the
  public wrappers reject empty input up front.
- **HMAC truncated-tag groups** — the SDK always returns the full 32-byte tag, so
  these groups compare the truncated tag and skip `HmacVerifyBytes`.
- **ML-DSA vectors with a context string, a hedged `rnd`, or a precomputed μ** —
  the SDK signs deterministically over the full message with an empty context.

### Not covered

- **ChaCha20-Poly1305, AES-GCM-SIV** — no Wycheproof tests yet; covered by the
  RFC 8439 / RFC 8452 vectors in their wrapper tests.
- **HMAC-SHA512** — not exposed by the .NET SDK.
- **Ascon** — Wycheproof only ships vectors for the pre-standard Ascon v1.2
  family; the SP 800-232 Ascon-AEAD128 that `cas-lib` implements is covered by
  NIST ACVP vectors.
- **RSA with other hashes, salt lengths or key sizes, and RSA encryption** — the SDK
  signs only RS256 and PS256 (SHA-256, 32-byte salt) with 2048/3072/4096-bit keys
  and has no RSA encryption.
- **ML-KEM seed-form / encaps / keygen vectors** — decapsulation takes the
  expanded 3168-byte key and encapsulation is randomized.
- **SLH-DSA** — no Wycheproof vectors exist yet; NIST ACVP covers it.
- **SHA-2 / SHA-3 / BLAKE2, password hashers, HPKE, zstd** — no applicable
  Wycheproof vector sets (SHA-2 and SHA-3 are covered by NIST CAVP).
