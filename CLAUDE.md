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

The Rust native library must be built and present alongside the managed assemblies, or all P/Invoke calls fail at runtime. The SDK `.csproj` automates this via MSBuild targets (`BuildRust` / `StageRustArtifacts`) that run `cargo build --release` before each build — so a plain `dotnet build` builds Rust too. This requires a working Rust toolchain (`cargo`) on PATH.

```bash
# Full build (also compiles the Rust submodule via the BuildRust target)
dotnet build cas-dotnet-sdk.sln

# Skip the Rust build when the native lib is already staged (much faster)
dotnet build cas-dotnet-sdk.sln -p:BuildNativeRust=false

# Build the Rust lib manually
cd cas-core-lib && cargo build --release

# Run all tests for one framework (must specify -f; the project multi-targets)
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -c Release -f net8.0

# Run a single test class or method
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 --filter "FullyQualifiedName~SHAWrapperTests"
dotnet test ./cas-dotnet-sdk-tests/cas-dotnet-sdk-tests.csproj -f net8.0 --filter "DisplayName~Hash512"
```

The same commands work for local development on macOS (Apple Silicon): a Rust toolchain on PATH builds `libcas_core_lib.dylib`, and the `StageRustArtifacts` MSBuild target stages it into `artifacts/native/osx-arm64/` automatically — no extra flags needed.

Note: CI (`.github/workflows/pr-tests-*.yml`) builds `cargo build --release` separately, then copies the native lib into the test `bin/Release/<tfm>` directory before running `dotnet test`. If you build the Rust lib by hand and the MSBuild target is skipped, the native artifact must end up next to the test assembly the same way.

## Architecture

Every cryptographic capability is grouped into a top-level folder by category (`Hashers`, `Symmetric`, `Asymmetric`, `Signatures`, `PasswordHashers`, `KeyExchange`, `Hybrid`, `Compression`, `Sponges`, `PQC`). Each category has the same structure:

1. **Public wrapper** (e.g. `Hashers/SHAWrapper.cs`) — the user-facing `unsafe` class, implementing a category interface where one exists (e.g. `IHasherBase`, `IPasswordHasherBase`). Each method pins its inputs with `fixed`, calls the generated binding on `NativeMethods`, checks the result's `error_code`, then copies the output into managed memory and frees the native allocation.

2. **Generated bindings** (`generated/NativeMethods.g.cs`) — `[DllImport]` declarations and C ABI result structs (e.g. `CasStringResult`, `CasVerifyResult`) emitted by csbindgen from `cas-core-lib/build.rs` during the `BuildRust` target. Never edit this file by hand.

3. **Types** (`<Category>/Types/*.cs`) — public result classes returned to callers (e.g. `Ed25519KeyPairResult`, `HpkeEncryptResult`), plus category enums.

### Cross-cutting helpers (`Helpers/`)

- `CasErrorHandler.ThrowIfError` — turns a non-zero `error_code` into a `CasException` (carrying `CasErrorCode` and the raw code). **Call it before reading any pointer from a result**: the native layer leaves pointers null on failure.
- `NativeByteBuffer.CopyAndFree` / `NativeString.ReadAndFree` — copy a native buffer or C string into managed memory and free it through the FFI. **Every pointer returned by the native layer must go through one of these**, or memory leaks. This is the single most important invariant when adding new wrappers.
- `NativeString.ToCString` — encodes a managed string as a null-terminated UTF-8 buffer for pinning.
- `NativePin.Of` — substitutes a non-empty sentinel for zero-length arrays so `fixed` yields a non-null pointer.

### Factories

Categories with interchangeable algorithms expose a `*Factory` (e.g. `HasherFactory.Get(IHasherType.SHA)`, `PasswordHasherFactory.Get(...)`) returning the category interface. When adding a new algorithm to such a category, wire it into both the enum and the factory switch.

### Tunable cost

The password hashers expose `HashPasswordWithParameters` alongside the default `HashPassword`: Argon2 (`memoryCost` KiB, `iterations`, `parallelism`), SCrypt (`cpuCost` as log2(N), `blockSize`, `parallelism`) and BCrypt (`cost`, max 31).

## Adding a new algorithm

1. Add the Rust FFI function in `cas-core-lib` (separate submodule/repo), returning a result struct with an `error_code`, and rebuild — csbindgen regenerates `generated/NativeMethods.g.cs`.
2. Implement the public method on the wrapper: pin inputs with `fixed`, call `NativeMethods`, `CasErrorHandler.ThrowIfError`, then marshal out with `NativeByteBuffer` / `NativeString`.
3. Add any new public result class to `Types/`.
4. If the category has a factory/enum, register the new type there.
5. Add an xUnit test. NIST test vectors live as `.rsp` files under the test project's `AES/Data` and `SHA/Data` folders (copied to output via `Content` items in the test `.csproj`).
6. Add a usage example to `docs/EXAMPLES.md` (see below).

## Keeping examples in sync

`docs/EXAMPLES.md` is the user-facing reference and must match the public API. **Whenever you add, rename, remove, or change the signature of a public method or result type, update `docs/EXAMPLES.md` in the same change** — do not leave it for a follow-up.

- **New method or algorithm:** add an example under its category heading (create the heading if needed), with the `using` lines and a round trip where one applies (encrypt + decrypt, sign + verify, hash + verify).
- **Tunable parameters / cost:** show the parameterized overload next to the default one and list each parameter with its unit, default, and limits (as the Password Hashers section does).
- **Renamed or removed APIs:** fix or delete every example that calls them; grep `docs/EXAMPLES.md` for the old name.
- **New result types:** use the real property names from `Types/` in the example.
- Also give the public method XML doc comments (`<summary>`, plus `<param>` for any tuning parameter).
- Keep the doc example-only: no benchmark tables or performance claims.

## Cross-platform constraint

Supported targets: **Windows x64**, **Linux x64**, and **macOS Apple Silicon** (`osx-arm64`). Intel macs (`osx-x64`) are intentionally not supported — the Intel runners were too slow for this project's CI. Since the csbindgen migration (#191), P/Invoke goes through the generated `generated/NativeMethods.g.cs` using the bare library name `cas_core_lib`; the .NET runtime resolves it per-OS to `cas_core_lib.dll` / `libcas_core_lib.so` / `libcas_core_lib.dylib`, so there are no per-platform `[DllImport]` files to keep in sync. The native lib is built (`cargo build --release`), staged into `artifacts/native/<rid>/`, and packed into `runtimes/<rid>/native` for each RID. Tests run against .NET 6–10 on all three OSes in CI on every PR: `pr-tests-windows` and `pr-tests-linux` fan out one job per TFM, while `pr-tests-macos-arm64` (`macos-latest`, Apple Silicon) runs all five target frameworks in a single `dotnet test` invocation (no `-f`). The `OperatingSystemDeterminator` resolves Windows, Linux, and OSX and throws on anything else.

Note: this is desktop **macOS / Darwin**, not iOS. Real iOS (`aarch64-apple-ios`) would need a cross-compiled native lib and a simulator/device to run tests, neither of which the current CI provides.
