# NIST test vectors

The NIST known-answer vectors are **downloaded, not committed**, like the Project
Wycheproof vectors (see `../PQC/Data/README.md`), and matching cas-typescript-sdk's
`scripts/fetch-nist.mjs`. The files the tests read come to about 18 MB of CAVP
`.rsp` files and 81 MB of ACVP JSON, almost all of it SLH-DSA.

`../build/NistVectors.targets` (imported by the test `.csproj`) runs the
`DownloadNistVectors` task (`../build/DownloadNistVectors.cs`) before every
`dotnet build` / `dotnet test`, locally and in CI:

| Source | What | Pinned by |
| --- | --- | --- |
| [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) on csrc.nist.gov | static zips (`NistCavpArchive` items); the members the tests read (`NistCavpFile`) are extracted | SHA-256 of the zip; each member's SHA-256 is recorded at extraction and re-checked every build |
| [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) `gen-val/json-files/<dir>/internalProjection.json` | one file per vector set (`NistAcvpFile` items), holding the inputs and expected results of every case | the release tag `NistAcvpPinnedRef` (`v1.1.0.43`), and the git blob SHA GitHub reports for each file at that tag |

- **Cache:** `cas-dotnet-sdk-tests/obj/nist/` (git-ignored), shared by every
  configuration and target framework. The task holds a cross-process lock, so the
  parallel per-framework builds of a plain `dotnet test` download each file once.
  A cached file that still matches its pin is never downloaded again. Delete the
  folder at any time.
- **Output:** the files are copied next to the test assembly as
  `NistVectors/cavp/<file>` and `NistVectors/acvp/<dir>/internalProjection.json`.
- **Mismatches:** a cached file that doesn't match its pin is downloaded (or
  re-extracted) again; a fresh download that doesn't match fails the build. Check
  what changed upstream before touching a pin.
- **Offline:** `-p:FetchNistVectors=false` never touches the network and uses
  (and checks) what is cached; the tests that need a missing file fail with a
  message saying so.

## Reading the vectors

- `RspFile.Read(file, recordKey)` parses the CAVP `.rsp` format: `#` comments,
  runs of `[key = value]` section headers, and blank-line separated blocks. A
  block holding the record key (`Count` by default, case-insensitive; `Len` for
  SHA ShortMsg/LongMsg, `SHAAlg` for RSA) is a vector; any other block holds
  section parameters (`n = ...`, `Seed = ...`) for the vectors after it. A bare
  `FAIL` line (GCMVS) or `Result = F (n - reason)` (RSA2VS) sets `Failed`.
- `AcvpFile.Load(dir, algorithm, mode)` reads an `internalProjection.json`, which
  already joins `prompt.json` with `expectedResults.json`, and returns every test
  case with its group (group values such as `parameterSet` or EdDSA's `d`/`q` are
  read through the case).
- `NistVectors.AssertCounts` pins how many vectors each test runs and skips. Every
  vector in a file is one or the other, so a filter that silently drops vectors,
  or a moved pin, fails the test.

## Coverage

| File | Test | Run | Skipped |
| --- | --- | ---: | ---: |
| `SHA{256,512}{Short,Long}Msg.rsp` | `SHA/SHA2WrapperTests` | 65 / 64 / 129 / 128 | 0 |
| `SHA3_{256,512}{Short,Long}Msg.rsp` | `SHA/SHAWrapperTests` | 137 / 100 / 73 / 100 | 0 |
| `SHA{256,512}Monte.rsp`, `SHA3_{256,512}Monte.rsp` | `NistShaMonteCarloTests` | 100 each | 0 |
| `gcmDecrypt{128,256}.rsp` (AAD decrypt) | `AES/AESWrapperTests` | 375 | 7500 |
| `gcmDecrypt{128,256}.rsp` (encrypt, no AAD) | `AES/AESWrapperTests` | 255 / 268 | 7620 / 7607 |
| `gcmDecrypt{128,256}.rsp` (`Aes*Open`) | `NistAesGcmTests` | 375 | 7500 |
| `gcmEncryptExtIV{128,256}.rsp` | `NistAesGcmTests` | 375 | 7500 |
| `HMAC.rsp` | `NistHmacTests` | 225 | 1350 |
| `SigGen15_186-3.txt` | `NistRsaTests` | 20 | 60 |
| `SigVer15_186-3.rsp` | `NistRsaTests` | 36 | 234 |
| `SigVerPSS_186-3.rsp` | `NistRsaTests` | 18 | 252 |
| `ML-KEM-encapDecap-FIPS203` (decapsulation) | `MLKEMWrapperTests` | 10 | 155 |
| `ML-KEM-encapDecap-FIPS203` (key checks) | `NistPqcTests` | 20 | 145 |
| `ML-DSA-sigVer-FIPS204` | `MLDSAWrapperTests` | 1 | 179 |
| `ML-DSA-keyGen-FIPS204` | `NistPqcTests` | 25 | 50 |
| `SLH-DSA-sigGen-FIPS205` | `NistPqcTests` | 1 | 623 |
| `SLH-DSA-sigVer-FIPS205` | `NistPqcTests` | 1 | 503 |
| `Ascon-AEAD128-SP800-232` | `NistAsconTests` | 7 | 233 |
| `EDDSA-KeyGen-1.0` | `NistEd25519Tests` | 3 | 3 |
| `EDDSA-SigGen-1.0` | `NistEd25519Tests` | 42 | 126 |
| `EDDSA-SigVer-1.0` | `NistEd25519Tests` | 5 | 15 |

`SigGen15_186-3.txt` is NIST's copy of `SigGen15_186-3.rsp` with the private
exponent `d` added for testing; the `.rsp` alone can't drive `RSAWrapper.Sign`.

### Skipped vectors, and why

Only what the SDK doesn't implement or its public API can't express is skipped:

- **Other algorithms and parameter sets:** SHA-1/224/384 HMAC sizes; RSA with
  hashes other than SHA-256 or moduli under 2048 bits (cas-lib rejects them);
  ML-KEM-512/768; ML-DSA-44/87; SLH-DSA sets other than SHAKE-128f; Ed448.
- **AES-GCM with non-96-bit IVs or non-128-bit tags** — the API takes a 96-bit
  nonce and appends a 128-bit tag (AES-192 has no file here). The 3-argument
  `Aes*Encrypt` test also skips vectors with AAD and `FAIL` vectors.
- **RSA-PSS with a salt other than 32 bytes** — the SDK verifies PS256 with a
  32-byte salt. PSS signing has a random salt, so `SigGenPSS` has no known answer.
- **Context strings, pre-hash, and the internal interfaces** (ML-DSA, SLH-DSA,
  EdDSA) — the SDK signs and verifies the external, pure interface with an empty
  context, deterministically. Non-deterministic SLH-DSA sigGen needs a caller
  `addrnd`. NIST's sample sets have only one SLH-DSA-SHAKE-128f sigGen and one
  sigVer case, and one ML-DSA-65 sigVer case, with an empty context.
- **ML-DSA sigGen** — not used: it gives the expanded signing key, and the API
  takes the 32-byte seed. keyGen is checked by signing with NIST's seed and
  verifying under NIST's public key.
- **ML-KEM encapsulation and keyGen** — they need the caller to supply `m` or
  `d`/`z`.
- **Ascon-AEAD128 with nonce masking or non-byte-aligned plaintext/AD** — the API
  has no second key and takes bytes. NIST tags are truncated to 32-128 bits: the
  ciphertext must match exactly and the tag must be a bit prefix of the SDK's
  128-bit tag (SP 800-232 orders bits least-significant first within a byte). A
  decryption case expected to fail is run only with a full 128-bit tag.

### No NIST validation program

AES-GCM-SIV, ChaCha20-Poly1305 (RFC vectors in their wrapper tests), X25519
(Wycheproof), HPKE, BLAKE2, the password hashers and zstd.
`Aes*KeyFromX25519SharedSecret` is HKDF-SHA256 with fixed labels and both public
keys in `info`, which NIST's KDA-HKDF vectors can't express.

## Refreshing

- **ACVP:** run
  `dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 -p:NistAcvpRef=<newer tag>`
  (or set `NIST_ACVP_REF`). Files from an unpinned ref aren't checked: the build
  warns and logs each one as `<dir>: BlobSha="..."`. Review the upstream changes;
  where a pinned vector count moved, check which vectors now run or are skipped
  and update the count. Then set `NistAcvpPinnedRef` to the tag and paste the
  logged `BlobSha` values into the `NistAcvpFile` items. Do it in its own PR.
- **CAVP:** the zips are static. To add or replace one, give its
  `NistCavpArchive` item an empty `Sha256`: the build downloads it, warns, and
  logs `Sha256="..."` to paste in. Add a `NistCavpFile` item (local name,
  `Archive`, `Member` path inside the zip) for each file a test reads.
- **New vector set:** add the item, read it with `RspFile.Read` /
  `AcvpFile.Load` via `NistVectors`, count every vector as run or skipped, pin
  both counts with `NistVectors.AssertCounts`, and add a row above.
