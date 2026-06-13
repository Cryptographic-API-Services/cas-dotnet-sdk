# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CAS .NET SDK is a managed cryptographic toolkit published as the [`cas-dotnet-sdk`](https://www.nuget.org/packages/cas-dotnet-sdk) NuGet package. It is a thin, high-level .NET API over a native Rust FFI layer (`cas-core-lib`), which itself wraps the RustCrypto and Dalek-Cryptography suites. The .NET code does almost no cryptography itself — it marshals data to/from the native library.

## Repository Layout

- `cas-dotnet-sdk/` — the SDK class library (NuGet package source). Multi-targets `net6.0`–`net10.0`.
- `cas-dotnet-sdk-tests/` — xUnit test project, references the SDK directly.
- `cas-core-lib/` — **git submodule** containing the Rust source compiled to `cas_core_lib.dll` (Windows) / `libcas_core_lib.so` (Linux). Clone with `--recursive` or run `git submodule update --init --recursive`.
- `docs/EXAMPLES.md` — usage samples.

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

Note: CI (`.github/workflows/pr-tests-*.yml`) builds `cargo build --release` separately, then copies the native lib into the test `bin/Release/<tfm>` directory before running `dotnet test`. If you build the Rust lib by hand and the MSBuild target is skipped, the native artifact must end up next to the test assembly the same way.

## Architecture: the three-layer wrapper pattern

Every cryptographic capability is grouped into a top-level folder by category (`Hashers`, `Symmetric`, `Asymmetric`, `Signatures`, `PasswordHashers`, `KeyExchange`, `Hybrid`, `Compression`, `Sponges`, `PQC`). Within each category folder, the same three-part structure repeats — understand it once and it applies everywhere:

1. **Public wrapper** (e.g. `Hashers/SHAWrapper.cs`) — the user-facing class. Inherits `BaseWrapper` and implements a category interface (e.g. `IHasherBase`). It contains the real logic: choose the platform DLL import, call it, copy the returned bytes out of the native pointer with `Marshal.Copy`, then free the native memory.

2. **Platform P/Invoke wrappers** (`<Category>/Windows/*.cs` and `<Category>/Linux/*.cs`) — `internal static` classes containing only `[DllImport]` declarations. Windows imports target `cas_core_lib.dll`, Linux imports target `libcas_core_lib.so`. The two files are otherwise identical signatures. The public wrapper dispatches between them with `this._platform == OSPlatform.Linux ? LinuxWrapper.fn(...) : WindowsWrapper.fn(...)`.

3. **Types** (`<Category>/Types/*.cs`) — `internal struct`s mirroring the C ABI structs returned by the Rust FFI (e.g. `SHAHashByteResult { IntPtr result_bytes_ptr; int length; }`), plus category interfaces and enums.

### Cross-cutting helpers (`Helpers/`)

- `BaseWrapper` — base class for all public wrappers; resolves the current OS into `_platform` (`OSPlatform`) at construction via `OperatingSystemDeterminator`. Throws on any OS that is not Windows or Linux.
- `FreeMemoryHelper` — frees native heap memory returned by the Rust layer. **Any FFI call that returns a pointer-bearing struct must have its pointer freed via `FreeMemoryHelper` after the bytes are marshaled out**, or memory leaks. This is the single most important invariant when adding new wrappers.

### Factories

Categories with interchangeable algorithms expose a `*Factory` (e.g. `HasherFactory.Get(IHasherType.SHA)`) returning the category interface. When adding a new algorithm to such a category, wire it into both the enum and the factory switch.

## Adding a new algorithm

1. Add the Rust FFI function in `cas-core-lib` (separate submodule/repo) and rebuild it.
2. Add matching `[DllImport]` declarations in **both** the `Windows` and `Linux` P/Invoke files of the relevant category.
3. Add any new return struct to `Types/`.
4. Implement the public method on the wrapper: platform-dispatch the call, marshal out the result, free native memory.
5. If the category has a factory/enum, register the new type there.
6. Add an xUnit test. NIST test vectors live as `.rsp` files under the test project's `AES/Data` and `SHA/Data` folders (copied to output via `Content` items in the test `.csproj`).

## Cross-platform constraint

Only **Windows x64** and **Linux x64** are supported (no macOS). All wrappers must keep Windows and Linux paths in sync — a function added to one platform wrapper without the other will throw `DllNotFoundException` / `EntryPointNotFoundException` on the missing platform. Tests run against .NET 6–10 on both OSes in CI on every PR.
