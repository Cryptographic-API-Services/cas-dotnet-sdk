# Test vectors (`PQC/Data`)

This folder holds the JSON known-answer vector files used by the test project.
They come from two sources and are handled differently.

## NIST ACVP vectors — committed

| File | Exercised by |
| --- | --- |
| `nist_mlkem_1024_decaps.json` | `MLKEMWrapperTests.NistDecapsulationVectors` |
| `nist_mldsa_65_sigver.json` | `MLDSAWrapperTests.NistSignatureVerificationVectors` |

These are trimmed NIST ACVP (FIPS 203/204) vectors and are **checked in**.

## Project Wycheproof vectors — downloaded, not committed

The `wycheproof_*.json` files are **not checked in** and never appear in this
folder. They are downloaded, unmodified, from the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) project (`testvectors_v1/`)
by the `FetchWycheproofVectors` MSBuild target in `cas-dotnet-sdk-tests.csproj`,
which runs automatically on every `dotnet build` / `dotnet test` — locally and in
CI — into `obj/<config>/<tfm>/wycheproof/`, and is copied next to the test
assembly as `PQC/Data/<local name>`. This matches the
[cas-typescript-sdk](https://github.com/Cryptographic-API-Services/cas-typescript-sdk)
approach, so the vectors never have to be manually re-committed.

Each target framework gets its own download folder because a plain
`dotnet test` builds all five frameworks in parallel; a shared folder makes
those builds collide ("the file is being used by another process").

| Local file | Upstream file | Exercised by |
| --- | --- | --- |
| `wycheproof_aes_gcm.json` | `aes_gcm_test.json` | `Wycheproof/AesGcmWycheproofTests.cs` |
| `wycheproof_ed25519.json` | `ed25519_test.json` | `Wycheproof/Ed25519WycheproofTests.cs` |
| `wycheproof_x25519.json` | `x25519_test.json` | `Wycheproof/X25519WycheproofTests.cs` |
| `wycheproof_hmac_sha256.json` | `hmac_sha256_test.json` | `Wycheproof/HmacWycheproofTests.cs` |
| `wycheproof_mlkem_1024_decaps.json` | `mlkem_1024_semi_expanded_decaps_test.json` | `MLKEMWrapperTests.WycheproofDecapsulationVectors` |
| `wycheproof_mldsa_65_sign.json` | `mldsa_65_sign_seed_test.json` | `MLDSAWrapperTests.WycheproofSigningVectors` |
| `wycheproof_mldsa_65_verify.json` | `mldsa_65_verify_test.json` | `MLDSAWrapperTests.WycheproofSignatureVerificationVectors` |

- **Always latest:** by default the target resolves upstream `main` to its
  current commit SHA (logged as `Fetching Wycheproof vectors from
  C2SP/wycheproof@<sha> (main)`) and tests against it. Files are re-downloaded
  only when that SHA changes; otherwise the build logs `Wycheproof vectors
  already at ...`. To reproduce an old run, pin the SHA from its log.
- **Pin a ref:** for a reproducible run, pass a commit SHA or tag:

  ```bash
  dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 -p:WycheproofRef=<sha-or-tag>
  ```

  or set the `WYCHEPROOF_REF` environment variable.
- **Offline:** if the ref can't be resolved (no network, or `git` not on PATH)
  and the vectors were downloaded before, they are reused with a build warning.
  `-p:FetchWycheproofVectors=false` skips the network entirely.
- **New failures:** a Wycheproof test that fails without any SDK change usually
  means upstream added a case the SDK (or the test) doesn't handle yet.
- **Adding a file:** add one `WycheproofVector` item to
  `cas-dotnet-sdk-tests.csproj` (local name as `Include`, upstream name as
  `Upstream`), add a row above, and load it with `PqcVectorData.Load(...)`.
- **Result semantics:** Wycheproof `result` is three-way. Tests assert `valid` and
  `invalid`; `acceptable` is allowed to go either way unless the algorithm
  defines a single correct output (X25519).

Wycheproof is licensed under the Apache License 2.0; see
<https://github.com/C2SP/wycheproof/blob/main/LICENSE>.

### Skipped vectors, and why

Tests skip only what the SDK's public API cannot express; skips are counted and
reported in the failure message.

- **AES-GCM with AAD, non-96-bit IVs, non-128-bit tags, or AES-192 keys** — the
  API has no AAD parameter, takes a 96-bit nonce, appends a 128-bit tag, and
  exposes only AES-128/256.
- **Ed25519 and HMAC vectors with an empty message (or empty HMAC key)** — the
  public wrappers reject empty input up front.
- **HMAC truncated-tag groups** — the SDK always returns the full 32-byte tag, so
  these groups compare the truncated tag and skip `HmacVerifyBytes`.
- **ML-DSA vectors with a context string, a hedged `rnd`, or a precomputed μ** —
  the SDK signs deterministically over the full message with an empty context.

### Not covered

- **ChaCha20-Poly1305, AES-GCM-SIV, HMAC-SHA512** — not exposed by the .NET SDK.
- **Ascon** — `cas-lib` implements NIST SP 800-232 Ascon-AEAD128; Wycheproof only
  ships vectors for the pre-standard Ascon v1.2 family.
- **RSA signatures** — `cas-lib` signs with unprefixed PKCS#1 v1.5 over raw data
  (no DigestInfo), so the `rsa_signature_*` vectors cannot match.
- **ML-KEM seed-form / encaps / keygen vectors** — decapsulation takes the
  expanded 3168-byte key and encapsulation is randomized.
- **SLH-DSA** — no Wycheproof vectors exist yet.
- **SHA-2 / SHA-3 / BLAKE2, password hashers, HPKE, zstd** — no applicable
  Wycheproof vector sets (SHA-3 is covered by the NIST `.rsp` files in `SHA/Data`).
