# cas-dotnet-sdk

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/7bXXCQj45q)

This .NET Nuget package is a cryptographic wrapper library for developers that are seeking the memory safety of Rust for their crypto implementations.

## [Sequential Examples / Benchmarks](./docs/EXAMPLES.md)

The official Nuget page can be found [here](https://www.nuget.org/packages/cas-dotnet-sdk).

## Consuming Library Documentation
This C# nuget package is dependent on our Rust layer that contains methods to run industry-standard cryptographic operations. [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib).

We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Supported Frameworks / Operating Systems
We aim to provide cross-compatibility wherever possible. 
- [X] .NET 6
- [X] .NET 7
- [X] .NET 8
- [X] .NET 9
- [X] Windows x64
- [X] Linux x64 (Ubuntu, if you are using Microsoft Docker images we recommend the noble images).
