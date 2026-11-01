### Symmetric
- AES 256

```csharp
using CasDotnetSdk.Symmetric;

AESWrapper aesWrapper = new AESWrapper();
byte[] nonceKey = aesWrapper.GenerateAESNonce();
byte[] key = aesWrapper.Aes256Key();
byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello World");
byte[] encrypted = aesWrapper.Aes256Encrypt(nonceKey, key, data);
byte[] decrypted = aesWrapper.Aes256Decrypt(nonceKey, key, encrypted);
```


### Signatures
- ED25519

```csharp
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;

ED25519Wrapper ed25519Wrapper = new ED25519Wrapper();
Ed25519KeyPairResult keyPair = ed25519Wrapper.GetKeyPair();
Ed25519ByteSignatureResult signature = ed25519Wrapper.SignBytes(keyPair.SigningKey, data);
bool isValid = ed25519Wrapper.VerifyWithPublicKeyBytes(signature.PublicKey, signature.Signature, data);
```


### Hashers
- SHA256

```csharp
using CasDotnetSdk.Hashers;

byte[] data = Encoding.UTF8.GetBytes("newShaToHash");
SHAWrapper shaWrapper = new SHAWrapper();
byte[] newSha = shaWrapper.Hash256(data);
```

- SHA512

```csharp
byte[] data = Encoding.UTF8.GetBytes("newShaToHash");
SHAWrapper shaWrapper = new SHAWrapper();
byte[] newSha = shaWrapper.Hash512(data);
```

- HMAC

```csharp
byte[] key = Encoding.UTF8.GetBytes("HmacKeyForSigning");
byte[] message = Encoding.UTF8.GetBytes("C#IsASuperDuperLanguage");
HmacWrapper hmacWrapper = new HmacWrapper();
byte[] hmacSigned = hmacWrapper.HmacSignBytes(key, message);
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
- `memoryCost`: memory to use, in KiB
- `iterations`: number of passes (time cost)
- `parallelism`: number of threads (lanes)

```csharp
Argon2Wrapper argon2Wrapper = new Argon2Wrapper();
string password = "DoNotDoThisWithMe!@#";
int memoryCost = 19456; // 19 MiB
int iterations = 2;
int parallelism = 1;
string hashed = argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, password);
bool isValid = argon2Wrapper.Verify(hashed, password);
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


### Error Handling
A failure in the native library throws a `CasException`. `ErrorCode` gives the failure category, and `RawErrorCode` keeps the native code.

```csharp
using CasDotnetSdk.Helpers;

try
{
    byte[] decrypted = aesWrapper.Aes256Decrypt(nonceKey, key, tamperedCiphertext);
}
catch (CasException ex)
{
    Console.WriteLine($"{ex.ErrorCode} ({ex.RawErrorCode}): {ex.Message}");
}
```
