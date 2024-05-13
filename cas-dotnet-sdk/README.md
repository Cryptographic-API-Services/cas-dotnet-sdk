# cas-dotnet-sdk

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/7bXXCQj45q)

Ever wanted all of your most useful cryptograpihc operations in one module and not have to surf documentation for various packages? 
CAS is here to provide a unified development experience as an abstract layer to the RustCrypto and Dalek-Cryptography suite of algorithms.

**Note: All work is experimental and we understand some benchmarks might not be the most optimal.**

## Consuming Library Documentation
This C# nuget package is dependent on our Rust layer that contains methods to run industry standard cryptographic operations sequentially, on threads, and the thread pool [cas-core-lib](https://github.com/Crytographic-API-Services/cas-core-lib).

We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)
- [Rayon](https://github.com/rayon-rs/rayon)


We recommend viewing our GitHub documentation for examples and benchmarks.
The url can be found [here](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk).

## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](https://github.com/Crytographic-API-Services/cas-core-lib) have never had a security audit performed. Utilize this SDK at your own risk.