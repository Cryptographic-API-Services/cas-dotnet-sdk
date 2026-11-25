using CasCoreLib;
using CasDotnetSdk.Helpers;
using System;

namespace CasDotnetSdk.Symmetric
{
    /// <summary>
    /// A wrapper class for ChaCha20-Poly1305 (RFC 8439) encryption and decryption with a 32-byte
    /// key and a 12-byte nonce.
    /// </summary>
    public unsafe class ChaCha20Poly1305Wrapper
    {
        public ChaCha20Poly1305Wrapper()
        {
        }

        /// <summary>
        /// Generates a 32-byte ChaCha20-Poly1305 key.
        /// </summary>
        public byte[] ChaCha20Poly1305Key()
        {
            CasCoreLib.ChaCha20Poly1305Key keyResult = NativeMethods.chacha20_poly1305_key();
            CasErrorHandler.ThrowIfError(keyResult.error_code, "ChaCha20-Poly1305 key generation");
            return NativeByteBuffer.CopyAndFree(keyResult.key, keyResult.length);
        }

        /// <summary>
        /// Generates a random 12-byte ChaCha20-Poly1305 nonce. Use it for one message only.
        /// </summary>
        public byte[] ChaCha20Poly1305Nonce()
        {
            CasCoreLib.ChaCha20Poly1305Nonce nonceResult = NativeMethods.chacha20_poly1305_nonce();
            CasErrorHandler.ThrowIfError(nonceResult.error_code, "ChaCha20-Poly1305 nonce generation");
            return NativeByteBuffer.CopyAndFree(nonceResult.nonce, nonceResult.length);
        }

        /// <summary>
        /// Encrypts with ChaCha20-Poly1305 under a fresh random 96-bit nonce and returns
        /// <c>nonce (12 bytes) || ciphertext || tag (16 bytes)</c>. This is the recommended way to
        /// encrypt: the caller never handles a nonce, so it cannot reuse one. Random 96-bit nonces
        /// are safe for about 2^32 messages per key (the NIST SP 800-38D bound); rotate the key
        /// before that.
        /// </summary>
        /// <param name="key">A 32-byte key from <see cref="ChaCha20Poly1305Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="ChaCha20Poly1305Open"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.InvalidKey"/> when the key is not 32 bytes.</exception>
        public byte[] ChaCha20Poly1305Seal(byte[] key, byte[] plaintext, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                // A null pointer with length 0 is an empty AAD.
                ChaCha20Poly1305EncryptResult result = NativeMethods.chacha20_poly1305_seal(keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 seal");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts a <c>nonce || ciphertext || tag</c> message produced by <see cref="ChaCha20Poly1305Seal"/>.
        /// </summary>
        /// <param name="key">The 32-byte key the message was sealed with.</param>
        /// <param name="sealedMessage">The output of <see cref="ChaCha20Poly1305Seal"/>.</param>
        /// <param name="aad">The same associated data passed to <see cref="ChaCha20Poly1305Seal"/>. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the message was tampered with or the key or AAD is wrong; <see cref="CasErrorCode.InvalidInput"/> when it is shorter than a nonce plus a tag.</exception>
        public byte[] ChaCha20Poly1305Open(byte[] key, byte[] sealedMessage, byte[]? aad = null)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(sealedMessage);

            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* sealedPtr = NativePin.Of(sealedMessage))
            fixed (byte* aadPtr = aad)
            {
                ChaCha20Poly1305DecryptResult result = NativeMethods.chacha20_poly1305_open(keyPtr, (nuint)key.Length, sealedPtr, (nuint)sealedMessage.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 open");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with ChaCha20-Poly1305 under a caller-supplied 12-byte nonce and returns
        /// <c>ciphertext || tag</c>. Never reuse a nonce under the same key: that reveals the XOR
        /// of the plaintexts and lets an attacker forge messages. Prefer
        /// <see cref="ChaCha20Poly1305Seal"/>, which manages the nonce.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="ChaCha20Poly1305Nonce"/>, used for this message only.</param>
        /// <param name="key">A 32-byte key from <see cref="ChaCha20Poly1305Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        public byte[] ChaCha20Poly1305Encrypt(byte[] nonce, byte[] key, byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            {
                ChaCha20Poly1305EncryptResult result = NativeMethods.chacha20_poly1305_encrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 encrypt");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts ChaCha20-Poly1305 <c>ciphertext || tag</c> from <see cref="ChaCha20Poly1305Encrypt(byte[], byte[], byte[])"/>.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 32-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key or nonce is wrong.</exception>
        public byte[] ChaCha20Poly1305Decrypt(byte[] nonce, byte[] key, byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(ciphertext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            {
                ChaCha20Poly1305DecryptResult result = NativeMethods.chacha20_poly1305_decrypt(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 decrypt");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }

        /// <summary>
        /// Encrypts with ChaCha20-Poly1305 and associated data under a caller-supplied 12-byte nonce,
        /// and returns <c>ciphertext || tag</c>. Never reuse a nonce under the same key. Prefer
        /// <see cref="ChaCha20Poly1305Seal"/>, which manages the nonce and also takes associated data.
        /// </summary>
        /// <param name="nonce">A 12-byte nonce from <see cref="ChaCha20Poly1305Nonce"/>, used for this message only.</param>
        /// <param name="key">A 32-byte key from <see cref="ChaCha20Poly1305Key"/>.</param>
        /// <param name="plaintext">The data to encrypt. May be empty.</param>
        /// <param name="aad">Associated data: authenticated, not encrypted, and not included in the result. It must match on <see cref="ChaCha20Poly1305Decrypt(byte[], byte[], byte[], byte[])"/>. <c>null</c> means empty.</param>
        public byte[] ChaCha20Poly1305Encrypt(byte[] nonce, byte[] key, byte[] plaintext, byte[]? aad)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(plaintext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* plaintextPtr = NativePin.Of(plaintext))
            fixed (byte* aadPtr = aad)
            {
                ChaCha20Poly1305EncryptResult result = NativeMethods.chacha20_poly1305_encrypt_with_aad(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, plaintextPtr, (nuint)plaintext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 encrypt with AAD");
                return NativeByteBuffer.CopyAndFree(result.ciphertext, result.length);
            }
        }

        /// <summary>
        /// Decrypts ChaCha20-Poly1305 <c>ciphertext || tag</c> produced with associated data.
        /// </summary>
        /// <param name="nonce">The nonce the data was encrypted with.</param>
        /// <param name="key">The 32-byte key the data was encrypted with.</param>
        /// <param name="ciphertext">The <c>ciphertext || tag</c> to decrypt.</param>
        /// <param name="aad">The same associated data passed on encryption. <c>null</c> means empty.</param>
        /// <exception cref="CasException"><see cref="CasErrorCode.DecryptionFailed"/> when the ciphertext was tampered with or the key, nonce or AAD is wrong.</exception>
        public byte[] ChaCha20Poly1305Decrypt(byte[] nonce, byte[] key, byte[] ciphertext, byte[]? aad)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(ciphertext);

            fixed (byte* noncePtr = NativePin.Of(nonce))
            fixed (byte* keyPtr = NativePin.Of(key))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            fixed (byte* aadPtr = aad)
            {
                ChaCha20Poly1305DecryptResult result = NativeMethods.chacha20_poly1305_decrypt_with_aad(noncePtr, (nuint)nonce.Length, keyPtr, (nuint)key.Length, ciphertextPtr, (nuint)ciphertext.Length, aadPtr, (nuint)(aad?.Length ?? 0));
                CasErrorHandler.ThrowIfError(result.error_code, "ChaCha20-Poly1305 decrypt with AAD");
                return NativeByteBuffer.CopyAndFree(result.plaintext, result.length);
            }
        }
    }
}
