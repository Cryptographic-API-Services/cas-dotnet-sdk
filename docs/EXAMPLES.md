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

Both parties derive the same AES key from their X25519 shared secret (see [Key Exchange](#key-exchange)) and both public keys. The key is HKDF-SHA256 output bound to the cipher, the key size and both public keys, which can be passed in either order. A low-order peer public key is rejected with `CasErrorCode.InvalidKey`. These methods return only the key: the nonce comes from `GenerateAESNonce`, is not secret, and is sent along with the ciphertext.

```csharp
using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Symmetric;

X25519Wrapper x25519 = new X25519Wrapper();
X25519SecretPublicKey alice = x25519.GenerateSecretAndPublicKey();
X25519SecretPublicKey bob = x25519.GenerateSecretAndPublicKey();
byte[] aliceSecret = x25519.GenerateSharedSecret(alice.SecretKey, bob.PublicKey).SharedSecret;
byte[] bobSecret = x25519.GenerateSharedSecret(bob.SecretKey, alice.PublicKey).SharedSecret;

AESWrapper aesWrapper = new AESWrapper();
byte[] aliceKey = aesWrapper.Aes256KeyFromX25519SharedSecret(aliceSecret, alice.PublicKey, bob.PublicKey);
byte[] bobKey = aesWrapper.Aes256KeyFromX25519SharedSecret(bobSecret, bob.PublicKey, alice.PublicKey); // same key as aliceKey
byte[] aes128Key = aesWrapper.Aes128KeyFromX25519SharedSecret(aliceSecret, alice.PublicKey, bob.PublicKey);

byte[] nonce = aesWrapper.GenerateAESNonce();
byte[] encrypted = aesWrapper.Aes256Encrypt(nonce, aliceKey, Encoding.UTF8.GetBytes("Hello World"));
byte[] decrypted = aesWrapper.Aes256Decrypt(nonce, bobKey, encrypted);
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

`GetKeyPair` accepts a key size of `2048`, `3072` or `4096` bits; anything else throws `ArgumentOutOfRangeException`. Keys are returned as PEM strings.

`SignPss` and `VerifyPss` use RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte random salt (PS256). **Prefer them for new code.** PSS signatures are randomized, so signing the same message twice gives two different signatures that both verify. They interoperate with standard PS256 implementations, such as .NET's `RSA.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)`.

`Sign` and `Verify` use RSASSA-PKCS1-v1_5 with SHA-256 (RS256), for interoperating with RS256 systems. The signatures verify with standard RS256 verifiers, such as .NET's `RSA.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)`.

All four take the message itself: it is hashed inside the library. A PSS signature doesn't verify with `Verify`, and an RS256 signature doesn't verify with `VerifyPss`.

```csharp
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;

RSAWrapper rsa = new RSAWrapper();
RsaKeyPairResult keyPair = rsa.GetKeyPair(4096);
byte[] data = Encoding.UTF8.GetBytes("Sign this with RSA");

// RSASSA-PSS (PS256), recommended for new code.
byte[] pssSignature = rsa.SignPss(keyPair.PrivateKey, data);
bool isPssValid = rsa.VerifyPss(keyPair.PublicKey, data, pssSignature);

// RSASSA-PKCS1-v1_5 (RS256), for RS256 interoperability.
byte[] signature = rsa.Sign(keyPair.PrivateKey, data);
bool isValid = rsa.Verify(keyPair.PublicKey, data, signature);
```


### Signatures
- ED25519

The signer keeps the 32-byte `SigningKey`; verifiers only need the 32-byte public key (`VerifyingKey`, also returned as `PublicKey` by `SignBytes`). Verify with `VerifyWithPublicKeyBytes`. Verification is strict: non-canonical signatures, small-order R components and small-order public keys are rejected.

```csharp
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;

ED25519Wrapper ed25519Wrapper = new ED25519Wrapper();
Ed25519KeyPairResult keyPair = ed25519Wrapper.GetKeyPair();
byte[] data = Encoding.UTF8.GetBytes("Sign this with Ed25519");
Ed25519ByteSignatureResult signature = ed25519Wrapper.SignBytes(keyPair.SigningKey, data);

// Verify with the signer's public key.
bool isValid = ed25519Wrapper.VerifyWithPublicKeyBytes(keyPair.VerifyingKey, signature.Signature, data);
```

`VerifyBytes(signingKey, signature, data)` is obsolete: it takes the signing key, so a verifier would have to hold it. It gives the same (strict) result as `VerifyWithPublicKeyBytes` and will be removed in a future major version.

```csharp
// Obsolete (compiler warning CS0618): use VerifyWithPublicKeyBytes instead.
bool isValidWithSigningKey = ed25519Wrapper.VerifyBytes(keyPair.SigningKey, signature.Signature, data);
```


### Post-Quantum Signatures
- SLH-DSA (SLH-DSA-SHAKE-128f, FIPS 205)
- ML-DSA (ML-DSA-65, FIPS 204)

SLH-DSA-SHAKE-128f signatures are deterministic and use an empty context. The signing key is
64 bytes, the verification key is 32 bytes and the signature is 17,088 bytes.

```csharp
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;

SLHDSAWrapper slhdsa = new SLHDSAWrapper();
SLHDSAKeyPair keyPair = slhdsa.GenerateSigningAndVerificationKey();
byte[] message = Encoding.UTF8.GetBytes("Sign this with SLH-DSA");
byte[] signature = slhdsa.Sign(keyPair.SigningKey, message);
bool isValid = slhdsa.Verify(keyPair.VerificationKey, signature, message);
```

ML-DSA-65 signatures are deterministic and use an empty context. The signing key is the
32-byte private seed; the verification key is 1952 bytes and the signature is 3309 bytes.

```csharp
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;

MLDSAWrapper mldsa = new MLDSAWrapper();
MLDSAKeyPair keyPair = mldsa.GenerateSigningAndVerificationKey();
byte[] message = Encoding.UTF8.GetBytes("Sign this with ML-DSA");

// Sign with the signing (seed) key...
byte[] signature = mldsa.Sign(keyPair.SigningKey, message);
// ...and verify with the verification (public) key.
bool isValid = mldsa.Verify(keyPair.VerificationKey, signature, message);
```


### Post-Quantum Key Encapsulation
- ML-KEM (ML-KEM-1024, FIPS 203)

The holder of the public key receives a ciphertext; both parties derive the same 32-byte
shared secret. The secret (decapsulation) key is 3168 bytes, the public (encapsulation) key
and the ciphertext are 1568 bytes each.

```csharp
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;

MLKEMWrapper mlkem = new MLKEMWrapper();
MLKemKeyPair keyPair = mlkem.GenerateKeyPair();

// Sender encapsulates to the recipient's public key.
MLKemEncapsulateResult encapsulated = mlkem.Encapsulate(keyPair.PublicKey);
byte[] senderSharedSecret = encapsulated.SharedSecret;

// Recipient decapsulates the ciphertext with their secret key.
byte[] recipientSharedSecret = mlkem.Decapsulate(keyPair.SecretKey, encapsulated.Ciphertext);
// senderSharedSecret and recipientSharedSecret are equal.
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

`null` and an empty array are both hashed as the empty message (the NIST `Len = 0` digest), so they give the same result. The expected hash passed to `Verify256` / `Verify512` must not be `null`.

```csharp
byte[] emptySha256 = shaWrapper.Hash256(null);
bool sameAsEmpty = emptySha256.SequenceEqual(shaWrapper.Hash256(Array.Empty<byte>())); // true
bool isEmptyValid = shaWrapper.Verify256(null, emptySha256); // true
```

- SHA-2 256 / 512 (SHA-256 / SHA-512)

`SHA2Wrapper` is FIPS 180-4 SHA-2; `SHAWrapper` above is SHA-3. The two give different digests for the same input. `null` input works the same way as in `SHAWrapper`.

```csharp
using CasDotnetSdk.Hashers;

SHA2Wrapper sha2Wrapper = new SHA2Wrapper();
byte[] data = Encoding.UTF8.GetBytes("newSha2ToHash");
byte[] sha256 = sha2Wrapper.Hash256(data);
byte[] sha512 = sha2Wrapper.Hash512(data);
bool isValid256 = sha2Wrapper.Verify256(data, sha256);
bool isValid512 = sha2Wrapper.Verify512(data, sha512);
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
IHasherBase hasher = HasherFactory.Get(IHasherType.Blake2); // or IHasherType.SHA (SHA-3), IHasherType.SHA2
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

`infoStr` is RFC 9180 application context that both sides agree on (at most 65,530 bytes). The optional `aad` argument binds the ciphertext to associated data, such as a record id or a header, that is authenticated but not encrypted. Decryption fails unless the recipient passes the same `aad`:

```csharp
byte[] aad = Encoding.UTF8.GetBytes("record-42");
HpkeEncryptResult bound = hpke.Encrypt(plaintext, keyPair.PublicKey, keyPair.InfoStr, aad);
byte[] opened = hpke.Decrypt(bound.Ciphertext, keyPair.PrivateKey, bound.EncappedKey, bound.Tag, keyPair.InfoStr, aad);
```


### Compression
- ZSTD

`level` ranges from `0` to `22` (`0` selects zstd's default); anything else throws `ArgumentOutOfRangeException`. Lower levels are faster; higher levels compress better. Decompression needs no level.

Decompression output is limited, so a small malicious frame can't exhaust memory. Output over the limit throws a `CasException` with `CasErrorCode.DecompressionLimitExceeded`.

- `Decompress(data)` allows up to 64 MiB of output.
- `Decompress(data, maxOutputSize)` allows up to `maxOutputSize` bytes. It must be greater than `0` (otherwise `ArgumentOutOfRangeException`) and can be above 64 MiB, up to `int.MaxValue`. Set it no higher than the largest output you expect from the data's source.

```csharp
using CasDotnetSdk.Compression;
using CasDotnetSdk.Helpers;

ZSTDWrapper zstd = new ZSTDWrapper();
byte[] data = Encoding.UTF8.GetBytes("Compress this text, compress this text, compress this text");
byte[] compressed = zstd.Compress(data, 3);

// Up to 64 MiB of output.
byte[] decompressed = zstd.Decompress(compressed);

// Up to a limit you choose, here 1 MiB.
try
{
    byte[] limited = zstd.Decompress(compressed, 1024 * 1024);
}
catch (CasException ex) when (ex.ErrorCode == CasErrorCode.DecompressionLimitExceeded)
{
    // The data would decompress to more than 1 MiB.
}
```


### Error Handling
A failure in the native library throws a `CasException`. `ErrorCode` gives the failure category, and `RawErrorCode` keeps the native code. A code this SDK version doesn't recognize maps to `CasErrorCode.Unknown`, never to `Success`.

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
