# CAS .NET SDK

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/UAGqKfmvUS)

## Overview

CAS .NET SDK is a comprehensive cryptographic toolkit for .NET, designed to provide developers with a unified, high-level interface to industry-standard cryptographic algorithms. This library acts as an abstraction layer over the powerful RustCrypto and Dalek-Cryptography suites, enabling secure and efficient cryptographic operations through a simple .NET API.

- **Official NuGet Package:** [cas-dotnet-sdk](https://www.nuget.org/packages/cas-dotnet-sdk)

## Features
- Modern cryptographic primitives: digital signatures (RSA, Ed25519), hashing, and more
- Seamless integration with [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) Rust FFI layer for optimal performance
- Unified interface: no need to manage multiple cryptography packages or surf disparate documentation
- Built on trusted, open-source cryptography libraries
- Cross-platform support: Windows x64, Linux x64
- Multi-framework support: .NET 6, 7, 8, 9

## Documentation & References
We build on the work of leading cryptography projects. For in-depth algorithm details and implementation notes, please refer to:
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Usage Examples
See practical usage and code samples in our [Examples](./docs/EXAMPLES.md).

## Supported Frameworks / Operating Systems
We aim to provide cross-compatibility wherever possible. Test cases are run on .NET 6-9 for Windows and Linux (Ubuntu) on each pull request and release to NuGet through GitHub Actions.
- [X] .NET 6
- [X] .NET 7
- [X] .NET 8
- [X] .NET 9
- [X] .NET 10
- [X] Windows x64
- [X] Linux x64

## Disclaimer
This SDK leverages several cryptographic crates via our core FFI [layer](https://github.com/Cryptographic-API-Services/cas-core-lib). Please note that many of these crates have not undergone formal security audits. Use this library at your own risk and always review the underlying cryptographic implementations for your security requirements.

---
For questions, support, or to contribute, join our Discord or visit the [GitHub repository](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk).