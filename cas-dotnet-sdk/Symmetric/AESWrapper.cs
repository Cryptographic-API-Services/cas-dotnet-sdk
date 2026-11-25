using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Symmetric
{
    public unsafe class AESWrapper 
    {
        /// <summary>
        /// A wrapper class for AES-GCM 128 and 256 bit encryption and decryption.
        /// </summary>
        public AESWrapper()
        {
        }

        /// <summary>
        /// Generates an AES 128 bit key.
        /// </summary>
        public byte[] Aes128Key()
        {
            AesKeyResult keyResult = NativeMethods.aes_128_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-128 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        public byte[] Aes256Key()
        {
            AesKeyResult keyResult = NativeMethods.aes_256_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-256 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Derives an AES-256-GCM key from an X25519 shared secret with HKDF-SHA256, bound to the
        /// cipher and to both parties' public keys. Generate the nonce separately with
        /// <see cref="GenerateAESNonce"/>; this method returns only the key.
        /// </summary>
        /// <param name="sharedSecret">The 32-byte shared secret from <c>X25519Wrapper.GenerateSharedSecret</c>.</param>
        /// <param name="publicKeyA">One party's 32-byte X25519 public key.</param>
        /// <param name="publicKeyB">The other party's 32-byte X25519 public key. The two public keys can be passed in either order, so both peers derive the same key.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the shared secret is all zero (a low-order peer public key) or a length is wrong.</exception>
        public byte[] Aes256KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB)
        {
            return KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB, NativeMethods.aes_256_key_from_x25519_diffie_hellman_shared_secret, "AES-256 key from X25519 shared secret");
        }

        /// <summary>
        /// Derives an AES-128-GCM key from an X25519 shared secret with HKDF-SHA256, bound to the
        /// cipher and to both parties' public keys. Generate the nonce separately with
        /// <see cref="GenerateAESNonce"/>; this method returns only the key.
        /// </summary>
        /// <param name="sharedSecret">The 32-byte shared secret from <c>X25519Wrapper.GenerateSharedSecret</c>.</param>
        /// <param name="publicKeyA">One party's 32-byte X25519 public key.</param>
        /// <param name="publicKeyB">The other party's 32-byte X25519 public key. The two public keys can be passed in either order, so both peers derive the same key.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the shared secret is all zero (a low-order peer public key) or a length is wrong.</exception>
        public byte[] Aes128KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB)
        {
            return KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB, NativeMethods.aes_128_key_from_x25519_diffie_hellman_shared_secret, "AES-128 key from X25519 shared secret");
        }

        private delegate AesNonceAndKeyFromX25519DiffieHellman X25519KdfFn(byte* sharedSecret, nuint sharedSecretLength, byte* publicKeyA, nuint publicKeyALength, byte* publicKeyB, nuint publicKeyBLength);

        private static byte[] KeyFromX25519SharedSecret(byte[] sharedSecret, byte[] publicKeyA, byte[] publicKeyB, X25519KdfFn nativeDerive, string operation)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new ArgumentException("You must provide an X25519 shared secret to derive an AES key.", nameof(sharedSecret));
            }
            if (publicKeyA == null || publicKeyA.Length == 0)
            {
                throw new ArgumentException("You must provide both X25519 public keys to derive an AES key.", nameof(publicKeyA));
            }
            if (publicKeyB == null || publicKeyB.Length == 0)
            {
                throw new ArgumentException("You must provide both X25519 public keys to derive an AES key.", nameof(publicKeyB));
            }

            fixed (byte* secretPtr = sharedSecret)
            fixed (byte* publicKeyAPtr = publicKeyA)
            fixed (byte* publicKeyBPtr = publicKeyB)
            {
                AesNonceAndKeyFromX25519DiffieHellman result = nativeDerive(secretPtr, (nuint)sharedSecret.Length, publicKeyAPtr, (nuint)publicKeyA.Length, publicKeyBPtr, (nuint)publicKeyB.Length);
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.aes_key_ptr, result.aes_key_ptr_length);
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM under a fresh random 96-bit nonce and returns
        /// <c>nonce (12 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce, so it cannot reuse one. Random 96-bit nonces
        /// are safe for about 2^32 messages per key (NIST SP 800-38D); rotate the key before that.
        /// </summary>
        /// <param name="key">A 32-byte key from <see cref="Aes256Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes256Open"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 32 bytes.</exception>
        public byte[] Aes256Seal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            return Seal(key, plaintext, aad, NativeMethods.aes_256_seal, "AES-256 seal");
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="Aes256Seal"/>.
        /// </summary>
        /// <param name="key">The 32-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="Aes256Seal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="Aes256Seal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] Aes256Open(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            return Open(key, sealedMessage, aad, NativeMethods.aes_256_open, "AES-256 open");
        }

        /// <summary>
        /// Encrypts with AES-128-GCM under a fresh random 96-bit nonce and returns
        /// <c>nonce (12 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce, so it cannot reuse one. Random 96-bit nonces
        /// are safe for about 2^32 messages per key (NIST SP 800-38D); rotate the key before that.
        /// </summary>
        /// <param name="key">A 16-byte key from <see cref="Aes128Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes128Open"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 16 bytes.</exception>
        public byte[] Aes128Seal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            return Seal(key, plaintext, aad, NativeMethods.aes_128_seal, "AES-128 seal");
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="Aes128Seal"/>.
        /// </summary>
        /// <param name="key">The 16-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="Aes128Seal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="Aes128Seal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] Aes128Open(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            return Open(key, sealedMessage, aad, NativeMethods.aes_128_open, "AES-128 open");
        }

        private delegate AesBytesEncrypt SealFn(byte* key, nuint keyLength, byte* plaintext, nuint plaintextLength, byte* aad, nuint aadLength);

        private delegate AesBytesDecrypt OpenFn(byte* key, nuint keyLength, byte* sealedMessage, nuint sealedMessageLength, byte* aad, nuint aadLength);

        private static byte[] Seal(byte[] key, byte[] plaintext, byte[]? aad, SealFn nativeSeal, string operation)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                // A null pointer with length 0 is an empty AAD.
                AesBytesEncrypt result = nativeSeal(keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        private static byte[] Open(byte[] key, byte[] sealedMessage, byte[]? aad, OpenFn nativeOpen, string operation)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(sealedMessage);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* sealedPtr = NativePin.Of(sealedMessage))
            fixed (byte* aadPtr = aad)
            {
                AesBytesDecrypt result = nativeOpen(keyPtr, (nuint)key.Length, sealedPtr, (nuint)sealedMessage.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM under a caller-supplied nonce and returns <c>ciphertext || tag</c>.
        /// Never reuse a nonce under the same key: that reveals the XOR of the plaintexts and lets
        /// an attacker forge messages. Prefer <see cref="Aes256Seal"/>, which manages the nonce.
        /// </summary>
        public byte[] Aes256Encrypt(byte[] nonceKey, byte[] key, byte[] toEncrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toEncrypt))
            {
                AesBytesEncrypt encryptResult = NativeMethods.aes_256_encrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toEncrypt.Length);
                CasErrorHandler.ThrowIfError(encryptResult.error_code, "AES-256 encrypt");
                return NativeByteBuffer.CopyAndFree(encryptResult.ciphertext, encryptResult.length);
            }
        }

        /// <summary>
        /// Decrypts with AES-256-GCM.
        /// </summary>
        public byte[] Aes256Decrypt(byte[] nonceKey, byte[] key, byte[] toDecrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(toDecrypt))
            {
                AesBytesDecrypt decryptResult = NativeMethods.aes_256_decrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)toDecrypt.Length);
                CasErrorHandler.ThrowIfError(decryptResult.error_code, "AES-256 decrypt");
                return NativeByteBuffer.CopyAndFree(decryptResult.plaintext, decryptResult.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-128-GCM under a caller-supplied nonce and returns <c>ciphertext || tag</c>.
        /// Never reuse a nonce under the same key: that reveals the XOR of the plaintexts and lets
        /// an attacker forge messages. Prefer <see cref="Aes128Seal"/>, which manages the nonce.
        /// </summary>
        public byte[] Aes128Encrypt(byte[] nonceKey, byte[] key, byte[] dataToEncrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(dataToEncrypt))
            {
                AesBytesEncrypt encryptResult = NativeMethods.aes_128_encrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)dataToEncrypt.Length);
                CasErrorHandler.ThrowIfError(encryptResult.error_code, "AES-128 encrypt");
                return NativeByteBuffer.CopyAndFree(encryptResult.ciphertext, encryptResult.length);
            }
        }

        /// <summary>
        /// Decrypts with AES-128-GCM.
        /// </summary>
        public byte[] Aes128Decrypt(byte[] nonceKey, byte[] key, byte[] dataToDecrypt)
        {
            fixed (byte* noncePtr = NativePin.Of(nonceKey))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* dataPtr = NativePin.Of(dataToDecrypt))
            {
                AesBytesDecrypt decryptResult = NativeMethods.aes_128_decrypt_bytes_with_key(noncePtr, (nuint)nonceKey.Length, keyPtr, (nuint)key.Length, dataPtr, (nuint)dataToDecrypt.Length);
                CasErrorHandler.ThrowIfError(decryptResult.error_code, "AES-128 decrypt");
                return NativeByteBuffer.CopyAndFree(decryptResult.plaintext, decryptResult.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM and associated data under a caller-supplied 12-byte nonce, and
        /// returns <c>ciphertext || tag</c>. Never reuse a nonce under the same key. Prefer
        /// <see cref="Aes256Seal"/>, which manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonceKey">A 12-byte nonce from <see cref="GenerateAESNonce"/>, used for this message only.</param>
        /// <param name="key">A 32-byte key from <see cref="Aes256Key"/>.</param>
        /// <param name="toEncrypt">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes256Decrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] Aes256Encrypt(byte[] nonceKey, byte[] key, byte[] toEncrypt, byte[]? aad)
        {
            return EncryptWithAad(nonceKey, key, toEncrypt, aad, NativeMethods.aes_256_encrypt_bytes_with_aad, "AES-256 encrypt with AAD");
        }

        /// <summary>
        /// Decrypts AES-256-GCM <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonceKey">The nonce the data was encrypted with.</param>
        /// <param name="key">The 32-byte key the data was encrypted with.</param>
        /// <param name="toDecrypt">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] Aes256Decrypt(byte[] nonceKey, byte[] key, byte[] toDecrypt, byte[]? aad)
        {
            return DecryptWithAad(nonceKey, key, toDecrypt, aad, NativeMethods.aes_256_decrypt_bytes_with_aad, "AES-256 decrypt with AAD");
        }

        /// <summary>
        /// Encrypts with AES-128-GCM and associated data under a caller-supplied 12-byte nonce, and
        /// returns <c>ciphertext || tag</c>. Never reuse a nonce under the same key. Prefer
        /// <see cref="Aes128Seal"/>, which manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonceKey">A 12-byte nonce from <see cref="GenerateAESNonce"/>, used for this message only.</param>
        /// <param name="key">A 16-byte key from <see cref="Aes128Key"/>.</param>
        /// <param name="dataToEncrypt">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes128Decrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] Aes128Encrypt(byte[] nonceKey, byte[] key, byte[] dataToEncrypt, byte[]? aad)
        {
            return EncryptWithAad(nonceKey, key, dataToEncrypt, aad, NativeMethods.aes_128_encrypt_bytes_with_aad, "AES-128 encrypt with AAD");
        }

        /// <summary>
        /// Decrypts AES-128-GCM <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonceKey">The nonce the data was encrypted with.</param>
        /// <param name="key">The 16-byte key the data was encrypted with.</param>
        /// <param name="dataToDecrypt">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] Aes128Decrypt(byte[] nonceKey, byte[] key, byte[] dataToDecrypt, byte[]? aad)
        {
            return DecryptWithAad(nonceKey, key, dataToDecrypt, aad, NativeMethods.aes_128_decrypt_bytes_with_aad, "AES-128 decrypt with AAD");
        }

        private delegate AesBytesEncrypt EncryptWithAadFn(byte* nonce, nuint nonceLength, byte* key, nuint keyLength, byte* plaintext, nuint plaintextLength, byte* aad, nuint aadLength);

        private delegate AesBytesDecrypt DecryptWithAadFn(byte* nonce, nuint nonceLength, byte* key, nuint keyLength, byte* ciphertext, nuint ciphertextLength, byte* aad, nuint aadLength);

        private static byte[] EncryptWithAad(byte[] nonce, byte[] key, byte[] plaintext, byte[]? aad, EncryptWithAadFn nativeEncrypt, string operation)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                AesBytesEncrypt result = nativeEncrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        private static byte[] DecryptWithAad(byte[] nonce, byte[] key, byte[] ciphertext, byte[]? aad, DecryptWithAadFn nativeDecrypt, string operation)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(ciphertext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            fixed (byte* aadPtr = aad)
            {
                AesBytesDecrypt result = nativeDecrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Generates a AES Nonce usuable for AES-128-GCM and AES-256-GCM.
        /// </summary>
        public byte[] GenerateAESNonce()
        {
            AesNonce nonceResult = NativeMethods.aes_nonce();
            CasErrorHandler.ThrowIfError(nonceResult.error_code, "AES nonce generation");
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }
    }
}
