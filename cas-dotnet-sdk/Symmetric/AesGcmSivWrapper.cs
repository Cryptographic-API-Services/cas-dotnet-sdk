using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Symmetric
{
    /// <summary>
    /// A wrapper class for AES-GCM-SIV (RFC 8452) 128 and 256 bit encryption and decryption.
    /// AES-GCM-SIV is nonce-misuse resistant: reusing a nonce under the same key only reveals
    /// whether two messages (with the same associated data) were identical, instead of breaking
    /// confidentiality and authenticity as it does with AES-GCM. Use it when unique nonces can't
    /// be guaranteed; the Seal/Open methods still pick a fresh random nonce for every message.
    /// </summary>
    public unsafe class AesGcmSivWrapper
    {
        public AesGcmSivWrapper()
        {
        }

        /// <summary>
        /// Generates a 16-byte AES-128-GCM-SIV key.
        /// </summary>
        public byte[] Aes128GcmSivKey()
        {
            AesGcmSivKey keyResult = NativeMethods.aes_128_gcm_siv_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-128-GCM-SIV key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates a 32-byte AES-256-GCM-SIV key.
        /// </summary>
        public byte[] Aes256GcmSivKey()
        {
            AesGcmSivKey keyResult = NativeMethods.aes_256_gcm_siv_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "AES-256-GCM-SIV key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates a random 12-byte nonce for AES-128-GCM-SIV and AES-256-GCM-SIV.
        /// </summary>
        public byte[] GenerateAesGcmSivNonce()
        {
            AesGcmSivNonce nonceResult = NativeMethods.aes_gcm_siv_nonce();
            CasErrorHandler.ThrowIfError(nonceResult.error_code, "AES-GCM-SIV nonce generation");
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }

        /// <summary>
        /// Encrypts with AES-128-GCM-SIV under a fresh random 96-bit nonce and returns
        /// <c>nonce (12 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce. Rotate the key before about 2^32 messages.
        /// </summary>
        /// <param name="key">A 16-byte key from <see cref="Aes128GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes128GcmSivOpen"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 16 bytes.</exception>
        public byte[] Aes128GcmSivSeal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            return Seal(key, plaintext, aad, NativeMethods.aes_128_gcm_siv_seal, "AES-128-GCM-SIV seal");
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="Aes128GcmSivSeal"/>.
        /// </summary>
        /// <param name="key">The 16-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="Aes128GcmSivSeal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="Aes128GcmSivSeal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] Aes128GcmSivOpen(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            return Open(key, sealedMessage, aad, NativeMethods.aes_128_gcm_siv_open, "AES-128-GCM-SIV open");
        }

        /// <summary>
        /// Encrypts with AES-256-GCM-SIV under a fresh random 96-bit nonce and returns
        /// <c>nonce (12 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce. Rotate the key before about 2^32 messages.
        /// </summary>
        /// <param name="key">A 32-byte key from <see cref="Aes256GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes256GcmSivOpen"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 32 bytes.</exception>
        public byte[] Aes256GcmSivSeal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            return Seal(key, plaintext, aad, NativeMethods.aes_256_gcm_siv_seal, "AES-256-GCM-SIV seal");
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="Aes256GcmSivSeal"/>.
        /// </summary>
        /// <param name="key">The 32-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="Aes256GcmSivSeal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="Aes256GcmSivSeal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] Aes256GcmSivOpen(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            return Open(key, sealedMessage, aad, NativeMethods.aes_256_gcm_siv_open, "AES-256-GCM-SIV open");
        }

        /// <summary>
        /// Encrypts with AES-128-GCM-SIV under a caller-supplied 12-byte nonce and returns
        /// <c>ciphertext || tag</c>. Reusing a nonce under the same key reveals whether two
        /// messages were identical. Prefer <see cref="Aes128GcmSivSeal"/>, which manages the nonce.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="GenerateAesGcmSivNonce"/>.</param>
        /// <param name="key">A 16-byte key from <see cref="Aes128GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        public byte[] Aes128GcmSivEncrypt(byte[] nonce, byte[] key, byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            {
                AesGcmSivEncryptResult result = NativeMethods.aes_128_gcm_siv_encrypt_bytes_with_key(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-128-GCM-SIV encrypt");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts AES-128-GCM-SIV <c>ciphertext || tag</c> from <see cref="Aes128GcmSivEncrypt(byte[], byte[], byte[])"/>.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 16-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key or nonce is wrong.</exception>
        public byte[] Aes128GcmSivDecrypt(byte[] nonce, byte[] key, byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(ciphertext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            {
                AesGcmSivDecryptResult result = NativeMethods.aes_128_gcm_siv_decrypt_bytes_with_key(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-128-GCM-SIV decrypt");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM-SIV under a caller-supplied 12-byte nonce and returns
        /// <c>ciphertext || tag</c>. Reusing a nonce under the same key reveals whether two
        /// messages were identical. Prefer <see cref="Aes256GcmSivSeal"/>, which manages the nonce.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="GenerateAesGcmSivNonce"/>.</param>
        /// <param name="key">A 32-byte key from <see cref="Aes256GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        public byte[] Aes256GcmSivEncrypt(byte[] nonce, byte[] key, byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            {
                AesGcmSivEncryptResult result = NativeMethods.aes_256_gcm_siv_encrypt_bytes_with_key(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-256-GCM-SIV encrypt");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts AES-256-GCM-SIV <c>ciphertext || tag</c> from <see cref="Aes256GcmSivEncrypt(byte[], byte[], byte[])"/>.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 32-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key or nonce is wrong.</exception>
        public byte[] Aes256GcmSivDecrypt(byte[] nonce, byte[] key, byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(ciphertext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            {
                AesGcmSivDecryptResult result = NativeMethods.aes_256_gcm_siv_decrypt_bytes_with_key(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "AES-256-GCM-SIV decrypt");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with AES-128-GCM-SIV and associated data under a caller-supplied 12-byte nonce,
        /// and returns <c>ciphertext || tag</c>. Prefer <see cref="Aes128GcmSivSeal"/>, which
        /// manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="GenerateAesGcmSivNonce"/>.</param>
        /// <param name="key">A 16-byte key from <see cref="Aes128GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes128GcmSivDecrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] Aes128GcmSivEncrypt(byte[] nonce, byte[] key, byte[] plaintext, byte[]? aad)
        {
            return EncryptWithAad(nonce, key, plaintext, aad, NativeMethods.aes_128_gcm_siv_encrypt_bytes_with_aad, "AES-128-GCM-SIV encrypt with AAD");
        }

        /// <summary>
        /// Decrypts AES-128-GCM-SIV <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 16-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] Aes128GcmSivDecrypt(byte[] nonce, byte[] key, byte[] ciphertext, byte[]? aad)
        {
            return DecryptWithAad(nonce, key, ciphertext, aad, NativeMethods.aes_128_gcm_siv_decrypt_bytes_with_aad, "AES-128-GCM-SIV decrypt with AAD");
        }

        /// <summary>
        /// Encrypts with AES-256-GCM-SIV and associated data under a caller-supplied 12-byte nonce,
        /// and returns <c>ciphertext || tag</c>. Prefer <see cref="Aes256GcmSivSeal"/>, which
        /// manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="GenerateAesGcmSivNonce"/>.</param>
        /// <param name="key">A 32-byte key from <see cref="Aes256GcmSivKey"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="Aes256GcmSivDecrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] Aes256GcmSivEncrypt(byte[] nonce, byte[] key, byte[] plaintext, byte[]? aad)
        {
            return EncryptWithAad(nonce, key, plaintext, aad, NativeMethods.aes_256_gcm_siv_encrypt_bytes_with_aad, "AES-256-GCM-SIV encrypt with AAD");
        }

        /// <summary>
        /// Decrypts AES-256-GCM-SIV <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 32-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] Aes256GcmSivDecrypt(byte[] nonce, byte[] key, byte[] ciphertext, byte[]? aad)
        {
            return DecryptWithAad(nonce, key, ciphertext, aad, NativeMethods.aes_256_gcm_siv_decrypt_bytes_with_aad, "AES-256-GCM-SIV decrypt with AAD");
        }

        private delegate AesGcmSivEncryptResult SealFn(byte* key, nuint keyLength, byte* plaintext, nuint plaintextLength, byte* aad, nuint aadLength);

        private delegate AesGcmSivDecryptResult OpenFn(byte* key, nuint keyLength, byte* sealedMessage, nuint sealedMessageLength, byte* aad, nuint aadLength);

        private delegate AesGcmSivEncryptResult EncryptWithAadFn(byte* nonce, nuint nonceLength, byte* key, nuint keyLength, byte* plaintext, nuint plaintextLength, byte* aad, nuint aadLength);

        private delegate AesGcmSivDecryptResult DecryptWithAadFn(byte* nonce, nuint nonceLength, byte* key, nuint keyLength, byte* ciphertext, nuint ciphertextLength, byte* aad, nuint aadLength);

        private static byte[] Seal(byte[] key, byte[] plaintext, byte[]? aad, SealFn nativeSeal, string operation)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                // A null pointer with length 0 is an empty AAD.
                AesGcmSivEncryptResult result = nativeSeal(keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
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
                AesGcmSivDecryptResult result = nativeOpen(keyPtr, (nuint)key.Length, sealedPtr, (nuint)sealedMessage.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

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
                AesGcmSivEncryptResult result = nativeEncrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
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
                AesGcmSivDecryptResult result = nativeDecrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, operation);
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }
    }
}
