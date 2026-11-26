# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CAS .NET SDK is a managed cryptographic toolkit published as the [`cas-dotnet-sdk`](https://www.nuget.org/packages/cas-dotnet-sdk) NuGet package. It is a thin, high-level .NET API over a native Rust FFI layer (`cas-core-lib`), which itself wraps the RustCrypto and Dalek-Cryptography suites. The .NET code does almost no cryptography itself — it marshals data to/from the native library.

## Repository Layout

- `cas-dotnet-sdk/` — the SDK class library (NuGet package source). Multi-targets `net6.0`–`net10.0`.
- `cas-dotnet-sdk-tests/` — xUnit test project, references the SDK directly.
- `cas-core-lib/` — **git submodule** containing the Rust source compiled to `cas_core_lib.dll` (Windows) / `libcas_core_lib.so` (Linux) / `libcas_core_lib.dylib` (macOS). Clone with `--recursive` or run `git submodule update --init --recursive`.
- `docs/EXAMPLES.md` — user-facing usage samples. Must be kept current with the public API (see "Keeping examples in sync").

## Build & Test

The Rust native library must be built and present alongside the managed assemblies, or all P/Invoke calls fail at runtime. The SDK `.csproj` automates this via MSBuild targets (`BuildRust` / `StageRustArtifacts`) that run `cargo build --release --locked` before each build — so a plain `dotnet build` builds Rust too. This requires a working Rust toolchain (`cargo`) on PATH; the version is pinned in `cas-core-lib/rust-toolchain.toml` (run `rustup toolchain install` in `cas-core-lib/` once). `--locked` builds the graph in the submodule's committed `Cargo.lock`. The target sets `CAS_DOTNET_BINDINGS_DIR` so cas-core-lib's `build.rs` writes the bindings into `cas-dotnet-sdk/generated/`; without it they go only to cargo's `OUT_DIR`.

```bash
# Full build (also compiles the Rust submodule via the BuildRust target)
dotnet build cas-dotnet-sdk.sln

# Skip the Rust build when the native lib is already staged (much faster)
dotnet build cas-dotnet-sdk.sln -p:BuildNativeRust=false

# Build the Rust lib manually
cd cas-core-lib && CAS_DOTNET_BINDINGS_DIR=../cas-dotnet-sdk/generated cargo build --release --locked

# Run all tests for one framework (must specify -f; the project multi-targets)
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -c Release -f net8.0

# Run a single test class or method
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 --filter "FullyQualifiedName~SHAWrapperTests"
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 --filter "DisplayName~Hash512"
```

The same commands work for local development on macOS (Apple Silicon): a Rust toolchain on PATH builds `libcas_core_lib.dylib`, and the `StageRustArtifacts` MSBuild target stages it into `artifacts/native/osx-arm64/` automatically — no extra flags needed.

Note: CI (`.github/workflows/pr-tests-*.yml`) builds `cargo build --release --locked` separately, then copies the native lib into the test `bin/Release/<tfm>` directory before running `dotnet test`. If you build the Rust lib by hand and the MSBuild target is skipped, the native artifact must end up next to the test assembly the same way (or stage it in `cas-dotnet-sdk/artifacts/native/<rid>/` *before* the build, which copies it next to the test assembly; the publish workflow does this with `-p:BuildNativeRust=false`).

### CI

- **PR workflows** (`pr-tests-{windows,linux,macos-arm64}.yml`) run on every PR whatever the base branch. After `dotnet test` they check that the committed `cas-dotnet-sdk/generated/NativeMethods.g.cs` matches the bindings the test build just regenerated (CRs stripped, since Windows checks it out with CRLF), and that the file really was regenerated. A PR that bumps the submodule without committing the regenerated bindings fails there. Their `dotnet test` also downloads the pinned NIST and Wycheproof vectors (see "Test vectors"); nothing caches them between runs.
- **`audit.yml`** runs `cargo audit --deny unsound --deny yanked` (cargo-audit pinned) on `cas-core-lib/Cargo.lock` on every PR, on push to `main` and weekly. No advisories are ignored; fixes land in cas-core-lib / cas-lib and arrive here as a submodule bump.
- **`main-push-nuget-publish.yml`** runs on push to `main`. Its `release-please` job opens or updates the release PR (see "Releases"); the rest runs only when merging that PR created a release, on its tag. Its `native` matrix job builds each RID with `--locked`, then runs `cargo test`, the same bindings check, and `dotnet test` on every TFM against the just-built library before uploading it; `pack-and-publish` needs all three and is the only job with `id-token: write` (NuGet Trusted Publishing). The .NET SDK it builds with is pinned by `DOTNET_SDK_VERSION` in that file (each job writes a `global.json` at run time; the repo has none, so local builds use any .NET 10 SDK). Bump it by hand.
- **Dependabot** (`.github/dependabot.yml`) proposes NuGet packages, GitHub Actions (SHA pins) and the `cas-core-lib` submodule weekly, with a 7-day cooldown. Security updates come from the repository's Dependabot security updates setting.
- All workflows grant `permissions: {}` at the top and the minimum per job, pin actions to commit SHAs with a `# vX.Y.Z` comment, check out with `persist-credentials: false`, and pass untrusted values to `run:` through `env:`, never `${{ }}` inside the script.

### Test vectors

No known-answer vectors are committed: the NIST and Project Wycheproof vectors are both **downloaded at build time** into git-ignored caches (matching `cas-typescript-sdk`), and the RFC vectors are inline in their tests.

**NIST vectors** (CAVP and ACVP) come from `cas-dotnet-sdk-tests/build/NistVectors.targets`, imported by the test `.csproj`. Its `FetchNistVectors` target runs the `DownloadNistVectors` task (`build/DownloadNistVectors.cs`, compiled by `RoslynCodeTaskFactory`; `build/**` is removed from `Compile`) before every `dotnet build`/`dotnet test`. It downloads the CAVP zips from csrc.nist.gov (`NistCavpArchive` items), each **pinned by SHA-256**, extracts the members the tests read (`NistCavpFile` items), and downloads `gen-val/json-files/<dir>/internalProjection.json` from usnistgov/ACVP-Server at the release tag `NistAcvpPinnedRef` (`NistAcvpFile` items), each **pinned by its git blob SHA** at that tag. Everything goes into one cache, `cas-dotnet-sdk-tests/obj/nist/` (about 120 MB, mostly the SLH-DSA JSON), **shared by all configurations and TFMs**: the task holds a cross-process mutex, so the parallel per-TFM builds download each file once. A cached file that matches its pin is never re-downloaded; one that doesn't is fetched (or re-extracted) again, and a fresh download that doesn't match fails the build. Files are copied to the output as `NistVectors/cavp/<file>` and `NistVectors/acvp/<dir>/internalProjection.json`. Tests reach them through `cas-dotnet-sdk-tests/Nist/`: `NistVectors` (paths), `RspFile` (the CAVP `.rsp` format: `[section]` headers, blank-line blocks keyed by `Count`/`Len`/`SHAAlg`, section parameters, `FAIL` / `Result = F (n - ...)`), and `AcvpFile` (an `internalProjection.json`, which already joins `prompt.json` with `expectedResults.json`). Every test counts each vector in its file as run or skipped and **pins both counts** with `NistVectors.AssertCounts`, so a filter can't silently drop vectors; skip only what the SDK doesn't implement or its public API can't express. `-p:FetchNistVectors=false` uses only the cache. **To refresh** in its own PR: `dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 -p:NistAcvpRef=<newer tag>` (or `NIST_ACVP_REF`) fetches unchecked and logs `BlobSha="..."` per file; review the upstream changes, update any pinned counts that moved after checking why, then set `NistAcvpPinnedRef` and paste the `BlobSha` values. A CAVP archive with an empty `Sha256` is downloaded with a warning and its `Sha256="..."` logged. Sources, coverage (run/skip counts per file) and skip rationale: `cas-dotnet-sdk-tests/Nist/README.md`.

**Project Wycheproof vectors:** The `FetchWycheproofVectors` MSBuild target in `cas-dotnet-sdk-tests.csproj` downloads the `testvectors_v1/` files listed as `WycheproofVector` items from a **pinned** [C2SP/wycheproof](https://github.com/C2SP/wycheproof) commit (`WycheproofCommit`) into `obj/<config>/<tfm>/wycheproof/` on every `dotnet build`/`dotnet test` — re-downloading only when the ref changes — checks each file against the SHA-256 in its item's `Sha256` metadata (a mismatch deletes the cached copy and fails the build), then copies them to the output as `PQC/Data/wycheproof_*.json`. The folder is **per target framework on purpose**: a plain `dotnet test` builds all TFMs in parallel, and a shared download folder makes them fail with "file is being used by another process". Try another ref with `-p:WycheproofRef=<branch, tag or sha>` (or `WYCHEPROOF_REF`); a branch or tag is resolved to a SHA with `git ls-remote` (logged). Files from any commit but `WycheproofCommit` aren't digest-checked: the build warns and logs each file's digest. **To refresh the pin**, in its own PR: run `dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 -p:WycheproofRef=main`, review the upstream diff, make the tests pass, then set `WycheproofCommit` to the logged SHA and paste the logged `Sha256="..."` values into the `WycheproofVector` items. If the ref can't be resolved (offline, no git) and vectors are cached, they're reused with a warning; `-p:FetchWycheproofVectors=false` skips the network entirely. Wycheproof suites cover AES-GCM, Ed25519, X25519, HMAC-SHA256 and RSA RS256/PS256 signatures (`cas-dotnet-sdk-tests/Wycheproof/`) plus ML-KEM decaps and ML-DSA sign/verify (in `MLKEMWrapperTests` / `MLDSAWrapperTests`). To add a file, add one `WycheproofVector` item (local name + `Upstream` + `Sha256` metadata) and load it with `PqcVectorData.Load`; skip (and count) only what the public API can't express, and let `acceptable` results go either way. When editing that target, qualify item metadata (`%(WycheproofVector.Identity)`): an unqualified `%(Filename)` inside the target rewrites the `TargetPath` of *other* `Content` items, silently copying the wrong file under another vector file's name, and `PreserveNewest` then never repairs the bad output copy. See `cas-dotnet-sdk-tests/PQC/Data/README.md` for the Wycheproof coverage table and skip rationale. When refreshing the pin, a Wycheproof test that fails without an SDK change usually means upstream added a case not handled yet.

## Architecture

Every cryptographic capability is grouped into a top-level folder by category (`Hashers`, `Symmetric`, `Asymmetric`, `Signatures`, `PasswordHashers`, `KeyExchange`, `Hybrid`, `Compression`, `Sponges`, `PQC`). Each category has the same structure:

1. **Public wrapper** (e.g. `Hashers/SHAWrapper.cs`) — the user-facing `unsafe` class, implementing a category interface where one exists (e.g. `IHasherBase`, `IPasswordHasherBase`). Each method pins its inputs with `fixed`, calls the generated binding on `NativeMethods`, checks the result's `error_code`, then copies the output into managed memory and frees the native allocation.

2. **Generated bindings** (`cas-dotnet-sdk/generated/NativeMethods.g.cs`) — `[DllImport]` declarations and C ABI result structs (e.g. `CasStringResult`, `CasVerifyResult`) emitted by csbindgen from `cas-core-lib/build.rs` during the `BuildRust` target. Never edit this file by hand.

3. **Types** (`<Category>/Types/*.cs`) — public result classes returned to callers (e.g. `Ed25519KeyPairResult`, `HpkeEncryptResult`), plus category enums.

### Cross-cutting helpers (`Helpers/`)

- `CasErrorHandler.ThrowIfError` — turns a non-zero `error_code` into a `CasException` (carrying `CasErrorCode` and the raw code). **Call it before reading any pointer from a result**: the native layer leaves pointers null on failure.
- `NativeByteBuffer.CopyAndFree` / `NativeString.ReadAndFree` — copy a native buffer or C string into managed memory and free it through the FFI (in a `finally`, so a failed copy can't leak). **Every pointer returned by the native layer must be freed exactly once**, through the native allocator so cas-core-lib's zeroizing allocator wipes it. This is the single most important invariant when adding new wrappers.
- **Multi-buffer results** (X25519/Ed25519/HPKE/RSA/PQC key pairs, Ed25519 signatures, HPKE encrypt, ML-KEM encapsulate) have a native `free_<struct>` function. Call `ThrowIfError` and read the fields with `NativeByteBuffer.Copy` / `NativeString.Read` inside a `try`, and call `NativeMethods.free_<struct>(&result)` in the `finally`. Never free their fields one by one.
- `NativeString.ToCString` — encodes a managed string as a null-terminated UTF-8 buffer for pinning.
- `NativePin.Of` — substitutes a non-empty sentinel for zero-length arrays so `fixed` yields a non-null pointer.

### Factories

Categories with interchangeable algorithms expose a `*Factory` (e.g. `HasherFactory.Get(IHasherType.SHA)`, `PasswordHasherFactory.Get(...)`) returning the category interface. When adding a new algorithm to such a category, wire it into both the enum and the factory switch.

### Tunable cost

The password hashers expose `HashPasswordWithParameters` alongside the default `HashPassword`: Argon2 (`memoryCost` in MiB — cas-lib multiplies it by 1024 — 19–4096, `iterations` 1–10, `parallelism` 1–16), SCrypt (`cpuCost` as log2(N) 10–20 and below 16 × `blockSize`, `blockSize` 1–32, `parallelism` 1–16) and BCrypt (`cost` 10–16). These bounds mirror cas-lib 0.7.0's constants exactly; the wrappers check them (as public `Min*`/`Max*` constants) and throw `ArgumentOutOfRangeException` before any cast, and never narrow an `int` with an unchecked cast. If cas-lib changes a bound, change the wrapper constant, its XML docs, the tests and `docs/EXAMPLES.md` together.

Passwords go to the native `*_bytes` exports as the full UTF-8 encoding plus its length (via `PasswordHashers/PasswordBytes`, which rejects null, empty and unpaired surrogates), so an embedded `'\0'` is hashed; clear the encoded buffer with `CryptographicOperations.ZeroMemory` in a `finally`. Don't call the deprecated C-string password exports. BCrypt also rejects passwords over 72 UTF-8 bytes. Argon2 key derivation takes a salt (`GenerateSalt`, at least 16 bytes); the salt-less `DeriveAES*Key(string)` overloads are `[Obsolete]`.

## Adding a new algorithm

1. Add the Rust FFI function in `cas-core-lib` (separate submodule/repo), returning a result struct with an `error_code`, bump the submodule, and rebuild — csbindgen regenerates `cas-dotnet-sdk/generated/NativeMethods.g.cs`. Commit the regenerated file with the submodule bump.
2. Implement the public method on the wrapper: pin inputs with `fixed`, call `NativeMethods`, `CasErrorHandler.ThrowIfError`, then marshal out with `NativeByteBuffer` / `NativeString`.
3. Add any new public result class to `Types/`.
4. If the category has a factory/enum, register the new type there.
5. Add an xUnit test, with NIST known-answer vectors where NIST has a validation program for the algorithm (see "Test vectors").
6. Add a usage example to `docs/EXAMPLES.md` (see below).

## Keeping examples in sync

`docs/EXAMPLES.md` is the user-facing reference and must cover **every public method** in `cas-dotnet-sdk/`. **Whenever you add, rename, remove, or change the signature of a public method or result type, update `docs/EXAMPLES.md` in the same change, without being asked** — this is part of the task, not a follow-up. A change to the public API is not done until its example is.

Before finishing any task that touches a public wrapper, run this coverage check from the repo root (Git Bash). It must print nothing; each `MISSING` line is a method without an example:

```bash
git grep -hoE "^\s+public [A-Za-z0-9<>\[\]]+ [A-Z][A-Za-z0-9]*\(" -- 'cas-dotnet-sdk/*.cs' ':!cas-dotnet-sdk/generated' ':!cas-dotnet-sdk/Helpers' \
  | sed -E 's/.* ([A-Za-z0-9]+)\($/\1/' | sort -u \
  | while read m; do grep -q "\.$m(" docs/EXAMPLES.md || echo "MISSING $m"; done
```

- **New method or algorithm:** add an example under its category heading (create the heading if needed), with the `using` lines and a round trip where one applies (encrypt + decrypt, sign + verify, hash + verify).
- **Tunable parameters / cost:** show the parameterized overload next to the default one and list each parameter with its unit, default, and limits (as the Password Hashers section does).
- **Argument order:** copy it from the wrapper's signature and the xUnit test, and run the snippet against the built native library when you can. Hash `Verify` methods differ: `SHAWrapper.Verify*(data, hash)` but `Blake2Wrapper.Verify*(hash, data)`.
- **Renamed or removed APIs:** fix or delete every example that calls them; grep `docs/EXAMPLES.md` for the old name.
- **New result types:** use the real property names from `Types/` in the example.
- Also give the public method XML doc comments (`<summary>`, plus `<param>` for any tuning parameter).
- Keep the doc example-only: no benchmark tables or performance claims.

## Releases

Releases are automated with release-please (`release-please-config.json`, `.release-please-manifest.json`), as in cas-lib, cas-core-lib and cas-typescript-sdk. Don't bump `<Version>` in `cas-dotnet-sdk.csproj` or edit `CHANGELOG.md` by hand. Every push to `main` opens or updates a `chore: release X.Y.Z` PR whose version and changelog come from the Conventional Commit PR titles since the last release (`feat!:` / `BREAKING CHANGE:` → major, `feat:` → minor, `fix:` → patch). Merging that PR tags `vX.Y.Z`, creates the GitHub Release, and only then does `main-push-nuget-publish.yml` build, test and push the package to NuGet.

## Cross-platform constraint

Supported targets: **Windows x64**, **Linux x64**, and **macOS Apple Silicon** (`osx-arm64`). Intel macs (`osx-x64`) are intentionally not supported — the Intel runners were too slow for this project's CI. Since the csbindgen migration (#191), P/Invoke goes through the generated `cas-dotnet-sdk/generated/NativeMethods.g.cs` using the bare library name `cas_core_lib`; the .NET runtime resolves it per-OS to `cas_core_lib.dll` / `libcas_core_lib.so` / `libcas_core_lib.dylib`, so there are no per-platform `[DllImport]` files to keep in sync. The native lib is built (`cargo build --release --locked`), staged into `artifacts/native/<rid>/`, and packed into `runtimes/<rid>/native` for each RID. Tests run against .NET 6–10 on all three OSes in CI on every PR: `pr-tests-windows` and `pr-tests-linux` fan out one job per TFM, while `pr-tests-macos-arm64` (`macos-latest`, Apple Silicon) runs all five target frameworks in a single `dotnet test` invocation (no `-f`).

Note: this is desktop **macOS / Darwin**, not iOS. Real iOS (`aarch64-apple-ios`) would need a cross-compiled native lib and a simulator/device to run tests, neither of which the current CI provides.
