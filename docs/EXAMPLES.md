# Examples

Examples for every public method in the SDK, grouped by category. Snippets assume `using System.Text;`.

- [Symmetric](#symmetric)
- [Sponges](#sponges)
- [Asymmetric](#asymmetric)
- [Signatures](#signatures)
- [Post-Quantum Signatures](#post-quantum-signatures)
- [Key Exchange](#key-exchange)
- [Hashers](#hashers)
- [Password Hashers](#password-hashers)
- [Hybrid Encryption](#hybrid-encryption)
- [Compression](#compression)
- [Error Handling](#error-handling)


### Symmetric
- AES 256 (GCM)

```csharp
using CasDotnetSdk.Symmetric;

AESWrapper aesWrapper = new AESWrapper();
byte[] nonce = aesWrapper.GenerateAESNonce();
byte[] key = aesWrapper.Aes256Key();
byte[] data = Encoding.UTF8.GetBytes("Hello World");
byte[] encrypted = aesWrapper.Aes256Encrypt(nonce, key, data);
byte[] decrypted = aesWrapper.Aes256Decrypt(nonce, key, encrypted);
```

- AES 128 (GCM)

```csharp
AESWrapper aesWrapper = new AESWrapper();
byte[] nonce = aesWrapper.GenerateAESNonce();
byte[] key = aesWrapper.Aes128Key();
byte[] data = Encoding.UTF8.GetBytes("Hello World");
byte[] encrypted = aesWrapper.Aes128Encrypt(nonce, key, data);
byte[] decrypted = aesWrapper.Aes128Decrypt(nonce, key, encrypted);
```

- AES key from an X25519 shared secret

Both parties derive the same AES key from their X25519 shared secret (see [Key Exchange](#key-exchange)). The nonce is not secret and is sent along with the ciphertext.

```csharp
AESWrapper aesWrapper = new AESWrapper();
byte[] aes256Key = aesWrapper.Aes256KeyNonceX25519DiffieHellman(sharedSecret);
byte[] aes128Key = aesWrapper.Aes128KeyNonceX25519DiffieHellman(sharedSecret);
byte[] nonce = aesWrapper.GenerateAESNonce();
byte[] encrypted = aesWrapper.Aes256Encrypt(nonce, aes256Key, Encoding.UTF8.GetBytes("Hello World"));
```


### Sponges
- Ascon 128

```csharp
using CasDotnetSdk.Sponges;

AsconWrapper ascon = new AsconWrapper();
byte[] key = ascon.Ascon128Key();
byte[] nonce = ascon.Ascon128Nonce();
byte[] data = Encoding.UTF8.GetBytes("Light weight encryption");
byte[] encrypted = ascon.Ascon128Encrypt(nonce, key, data);
byte[] decrypted = ascon.Ascon128Decrypt(nonce, key, encrypted);
```


### Asymmetric
- RSA

`GetKeyPair` accepts a key size of `1024`, `2048` or `4096`. Keys are returned as strings.

```csharp
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;

RSAWrapper rsa = new RSAWrapper();
RsaKeyPairResult keyPair = rsa.GetKeyPair(4096);
byte[] data = Encoding.UTF8.GetBytes("Sign this with RSA");
byte[] signature = rsa.Sign(keyPair.PrivateKey, data);
bool isValid = rsa.Verify(keyPair.PublicKey, data, signature);
```


### Signatures
- ED25519

```csharp
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;

ED25519Wrapper ed25519Wrapper = new ED25519Wrapper();
Ed25519KeyPairResult keyPair = ed25519Wrapper.GetKeyPair();
byte[] data = Encoding.UTF8.GetBytes("Sign this with Ed25519");
Ed25519ByteSignatureResult signature = ed25519Wrapper.SignBytes(keyPair.SigningKey, data);

// Verify with the signing key pair you hold...
bool isValid = ed25519Wrapper.VerifyBytes(keyPair.SigningKey, signature.Signature, data);
// ...or with only the public key, as a recipient would.
bool isValidPublic = ed25519Wrapper.VerifyWithPublicKeyBytes(signature.PublicKey, signature.Signature, data);
```


### Post-Quantum Signatures
- SLH-DSA

```csharp
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;

SLHDSAWrapper slhdsa = new SLHDSAWrapper();
SLHDSAKeyPair keyPair = slhdsa.GenerateSigningAndVerificationKey();
byte[] message = Encoding.UTF8.GetBytes("Sign this with SLH-DSA");
byte[] signature = slhdsa.Sign(keyPair.SigningKey, message);
bool isValid = slhdsa.Verify(keyPair.VerificationKey, signature, message);
```


### Key Exchange
- X25519

Each party generates a key pair, swaps public keys, and computes the same shared secret.

```csharp
using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;

X25519Wrapper x25519 = new X25519Wrapper();
X25519SecretPublicKey alice = x25519.GenerateSecretAndPublicKey();
X25519SecretPublicKey bob = x25519.GenerateSecretAndPublicKey();

X25519SharedSecret aliceShared = x25519.GenerateSharedSecret(alice.SecretKey, bob.PublicKey);
X25519SharedSecret bobShared = x25519.GenerateSharedSecret(bob.SecretKey, alice.PublicKey);
// aliceShared.SharedSecret and bobShared.SharedSecret are equal.
byte[] sharedSecret = aliceShared.SharedSecret;
```


### Hashers
- SHA3 256 / 512

```csharp
using CasDotnetSdk.Hashers;

SHAWrapper shaWrapper = new SHAWrapper();
byte[] data = Encoding.UTF8.GetBytes("newShaToHash");
byte[] sha256 = shaWrapper.Hash256(data);
byte[] sha512 = shaWrapper.Hash512(data);
bool isValid256 = shaWrapper.Verify256(data, sha256);
bool isValid512 = shaWrapper.Verify512(data, sha512);
```

- Blake2 256 / 512

```csharp
Blake2Wrapper blake2 = new Blake2Wrapper();
byte[] data = Encoding.UTF8.GetBytes("BlakeToHash");
byte[] blake256 = blake2.Hash256(data);
byte[] blake512 = blake2.Hash512(data);
bool isValid256 = blake2.Verify256(blake256, data);
bool isValid512 = blake2.Verify512(blake512, data);
```

- HMAC

```csharp
HmacWrapper hmacWrapper = new HmacWrapper();
byte[] key = Encoding.UTF8.GetBytes("HmacKeyForSigning");
byte[] message = Encoding.UTF8.GetBytes("C#IsASuperDuperLanguage");
byte[] signature = hmacWrapper.HmacSignBytes(key, message);
bool isValid = hmacWrapper.HmacVerifyBytes(key, message, signature);
```

- Hasher factory

`HasherFactory` returns an `IHasherBase` so the algorithm can be picked at runtime.

```csharp
IHasherBase hasher = HasherFactory.Get(IHasherType.Blake2); // or IHasherType.SHA
byte[] hashed = hasher.Hash512(Encoding.UTF8.GetBytes("Factory hashing"));
```


### Password Hashers
- Argon2

```csharp
using CasDotnetSdk.PasswordHashers;

Argon2Wrapper argon2Wrapper = new Argon2Wrapper();
string password = "DoNotDoThisWithMe!@#";
string hashed = argon2Wrapper.HashPassword(password);
bool isValid = argon2Wrapper.Verify(hashed, password);
```

Set the cost with `HashPasswordWithParameters`. Higher values are slower and harder to brute force.
- `memoryCost`: memory to use, in **MiB** (the native layer multiplies by 1024 to get KiB)
- `iterations`: number of passes (time cost)
- `parallelism`: number of threads (lanes)

```csharp
Argon2Wrapper argon2Wrapper = new Argon2Wrapper();
string password = "DoNotDoThisWithMe!@#";
int memoryCost = 19; // 19 MiB
int iterations = 2;
int parallelism = 1;
string hashed = argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, password);
bool isValid = argon2Wrapper.Verify(hashed, password);
```

Derive an AES key from a password with Argon2.

```csharp
Argon2Wrapper argon2Wrapper = new Argon2Wrapper();
byte[] aes256Key = argon2Wrapper.DeriveAES256Key("DoNotDoThisWithMe!@#"); // 32 bytes
byte[] aes128Key = argon2Wrapper.DeriveAES128Key("DoNotDoThisWithMe!@#"); // 16 bytes
```

- SCrypt

```csharp
SCryptWrapper scrypt = new SCryptWrapper();
string password = "SCryptPasswordHash!@#$";
string hashed = scrypt.HashPassword(password);
bool isValid = scrypt.Verify(hashed, password);
```

Set the cost with `HashPasswordWithParameters`. Every parameter has a default.
- `cpuCost`: CPU/memory cost as log2(N), default `17` (N = 131072)
- `blockSize`: block size (r), default `8`
- `parallelism`: parallelization (p), default `1`

```csharp
SCryptWrapper scrypt = new SCryptWrapper();
string password = "SCryptPasswordHash!@#$";
string hashed = scrypt.HashPasswordWithParameters(password, cpuCost: 16, blockSize: 8, parallelism: 2);
bool isValid = scrypt.Verify(hashed, password);
```

- BCrypt

```csharp
BcryptWrapper bcrypt = new BcryptWrapper();
string password = "BCryptPasswordHasher!@#$%";
string hashed = bcrypt.HashPassword(password);
bool isValid = bcrypt.Verify(hashed, password);
```

Set the cost with `HashPasswordWithParameters`. `cost` is the log2 work factor, so each +1 doubles the hashing time. Default `12`, max `31`.

```csharp
BcryptWrapper bcrypt = new BcryptWrapper();
string password = "BCryptPasswordHasher!@#$%";
uint cost = 14;
string hashed = bcrypt.HashPasswordWithParameters(password, cost);
bool isValid = bcrypt.Verify(hashed, password);
```

- Password hasher factory

`PasswordHasherFactory` returns an `IPasswordHasherBase` (default cost) so the algorithm can be picked at runtime.

```csharp
IPasswordHasherBase hasher = PasswordHasherFactory.Get(PasswordHasherType.Argon2); // or BCrypt, SCrypt
string hashed = hasher.HashPassword("FactoryPassword!@#");
bool isValid = hasher.Verify(hashed, "FactoryPassword!@#");
```


### Hybrid Encryption
- HPKE

```csharp
using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;

HpkeWrapper hpke = new HpkeWrapper();
HpkeKeyPairResult keyPair = hpke.GenerateKeyPair();
byte[] plaintext = Encoding.UTF8.GetBytes("What is that? A New Router that I see?");
HpkeEncryptResult encrypted = hpke.Encrypt(plaintext, keyPair.PublicKey, keyPair.InfoStr);
byte[] decrypted = hpke.Decrypt(encrypted.Ciphertext, keyPair.PrivateKey, encrypted.EncappedKey, encrypted.Tag, keyPair.InfoStr);
```


### Compression
- ZSTD

`level` ranges from `-22` to `22`. Lower levels are faster; higher levels compress better. Decompression needs no level.

```csharp
using CasDotnetSdk.Compression;

ZSTDWrapper zstd = new ZSTDWrapper();
byte[] data = Encoding.UTF8.GetBytes("Compress this text, compress this text, compress this text");
byte[] compressed = zstd.Compress(data, 3);
byte[] decompressed = zstd.Decompress(compressed);
```


### Error Handling
A failure in the native library throws a `CasException`. `ErrorCode` gives the failure category, and `RawErrorCode` keeps the native code.

```csharp
using CasDotnetSdk.Helpers;

try
{
    byte[] decrypted = aesWrapper.Aes256Decrypt(nonce, key, tamperedCiphertext);
}
catch (CasException ex)
{
    Console.WriteLine($"{ex.ErrorCode} ({ex.RawErrorCode}): {ex.Message}");
}
```
