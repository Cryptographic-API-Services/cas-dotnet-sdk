# cas-dotnet-sdk benchmarks

[BenchmarkDotNet](https://github.com/dotnet/BenchmarkDotNet) suite for the SDK's public API. Each benchmark calls a wrapper the way an application would, so the numbers include the managed-to-native marshalling as well as the Rust cryptography.

| Class | What it measures |
| --- | --- |
| `HasherBenchmarks` | SHA3-256/512, SHA-256/512, BLAKE2s-256, BLAKE2b-512 over 1 KiB and 1 MiB |
| `HmacBenchmarks` | HMAC-SHA256 sign and verify over 1 KiB and 1 MiB |
| `SymmetricBenchmarks` | AES-128/256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305, Ascon-128 seal and open over 1 KiB and 1 MiB |
| `RsaBenchmarks` | RSA PKCS#1 v1.5 and PSS sign and verify, 2048- and 4096-bit keys |
| `RsaKeyGenerationBenchmarks` | RSA-2048 key generation |
| `Ed25519Benchmarks` | Ed25519 key generation, sign, verify |
| `X25519Benchmarks` | X25519 key generation and shared secret |
| `HpkeBenchmarks` | HPKE key generation, encrypt, decrypt (1 KiB) |
| `MLKEMBenchmarks` | ML-KEM-1024 key generation, encapsulate, decapsulate |
| `MLDSABenchmarks` | ML-DSA-65 key generation, sign, verify |
| `SLHDSABenchmarks` | SLH-DSA-SHAKE-128f key generation, sign, verify |
| `PasswordHasherBenchmarks` | Argon2, BCrypt and SCrypt hash and verify at the default cost, Argon2 key derivation |
| `ZstdBenchmarks` | Zstd compress and decompress 1 MiB at levels 1, 3 and 19 |

Inputs are deterministic (seeded), so every run hashes and encrypts the same bytes. The memory diagnoser is on, so the `Allocated` column shows managed allocations per call.

## Running locally

The project builds the SDK and its native library like the test project does, so you need the Rust toolchain on PATH (see the root `CLAUDE.md`). Always run in Release.

```bash
# Pick benchmarks from an interactive menu
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0

# Everything, with the quick ShortRun job (a few minutes per class)
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0 -- --filter '*' --job short

# One class, or one category
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0 -- --filter '*MLKEM*'
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0 -- --anyCategories PostQuantum

# Check every benchmark still runs (each runs once; the timings mean nothing)
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0 -- --filter '*' --job dry

# Compare .NET versions in one run (the host project targets net8.0, net9.0 and net10.0)
dotnet run -c Release --project cas-dotnet-sdk-benchmarks -f net10.0 -- --filter '*Hasher*' --runtimes net8.0 net10.0
```

Categories: `Hashing`, `Symmetric`, `Asymmetric`, `PostQuantum`, `PasswordHashing`, `Compression`, `KeyGeneration`. `--list flat` lists every benchmark, and `--help` shows all of BenchmarkDotNet's options.

If the native library is already built and staged in `cas-dotnet-sdk/artifacts/native/<rid>/`, add `-p:BuildNativeRust=false` before the `--` to skip the Rust build. BenchmarkDotNet builds each run in a generated project that references this one; that build always skips the Rust build and uses the staged library.

Results go to `BenchmarkDotNet.Artifacts/results/` (ignored by git) unless you pass `--artifacts <dir>`.

## CI

`.github/workflows/benchmarks.yml` runs the suite on `ubuntu-latest`:

- **Pull requests:** a dry run (`--job dry`), so a PR that breaks a benchmark fails. The timings aren't meaningful.
- **Push to `main`:** a `--job short` run. The results table is in the run's job summary, and the full reports (Markdown, JSON, CSV, HTML) are in its `benchmark-results` artifact for 90 days.
- **Manual (`workflow_dispatch`):** choose the `--filter` and the job (`dry`, `short`, `medium`, `long`).

The program exits with a non-zero code if any benchmark fails, so a broken benchmark fails the workflow. Hosted runners are shared VMs: compare runs on the same runner type, and expect a few percent of noise.

## Adding a benchmark

Add a public method with `[Benchmark(Description = "...")]` to the class for its category under `Benchmarks/` (or a new public class with a `[BenchmarkCategory]` from `Categories`). Build inputs in a `[GlobalSetup]` method, not in the benchmark, and return the result so the JIT can't drop the call. When you add an algorithm to the SDK, add its benchmark in the same change.
